// Package upstream — 出站身份选择（desktop / cli / vscode）。
//
// 依据 Hub v1.7.33 的官方包解包与抓包核对（见 protocol_profile.go E5）：
//   - desktop：既有默认（身份矩阵），全路径零漂移；
//   - cli：官方 CodeBuddy CLI 2.168.2 的 chat 头族（npm 包解包）；
//   - vscode：官方 VSCode 扩展 4.12.39997873 的 chat 头族（Open VSX 解包）。
//
// 选择规则：config upstream.outbound_identity = ""/"desktop"（默认，零回归）
// | "cli" | "vscode" | "auto"（按账号 uid 稳定哈希，在 upstream.outbound_identities
// 允许名单内轮换；名单缺省 ["desktop"]，即 auto 未扩名单时行为=desktop）。
// billing / refresh / models / 任务上报等非 chat 路径恒为 desktop 身份（官方旁路
// 链路没有 CLI/VSCode 形态，不扩散）。
package upstream

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"runtime"
	"strings"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
)

// 出站身份名（配置与内部选择共用）。
const (
	OutboundIdentityDesktop = "desktop"
	OutboundIdentityCLI     = "cli"
	OutboundIdentityVSCode  = "vscode"
	OutboundIdentityAuto    = "auto"
)

// CLI 身份常量（E5：官方 npm 包 @tencent-ai/codebuddy-code 2.168.2 解包核对）。
const (
	cliIDEVersionDefault = "2.168.2"
	// 官方 CLI UA 公式（buildUserAgent）：platform/platformVersion + productName/
	// productVersion；platform=CLI、productName=CodeBuddy、applicationName 空 →
	// 两段同版本号。
	cliUAFormat = "CLI/%s CodeBuddy/%s"
	// X-Agent-Runtime：官方枚举 local-agent/cloud-agent/agent-agent，未知/缺省
	// 解析为 "other"；主对话无覆盖 → other。
	cliAgentRuntime = "other"
	// 官方 OpenAI Node SDK 6.25.0 的 x-stainless-* 指纹头（os/arch/node 取网关
	// 宿主，与 TLS/网络栈一致；可被 config 覆盖对齐真实宿主）。
	cliStainlessSDKVersion = "6.25.0"
	cliStainlessRuntime    = "node"
	cliStainlessTimeout    = "1200"
	// 官方 CLI 的 chat 请求体默认 gzip（productFeatures.RequestBodyGzip）并注入
	// cache_retention=long；这三个 Responses API / 客户端自定义字段要剔掉。
	cliCacheRetentionDefault = "long"
)

// VSCode 身份常量（E5：Open VSX `Tencent-Cloud.coding-copilot` 4.12.39997873 解包）。
const (
	vscodeProductVersionDefault = "4.12.39997873"
	vscodeIDEVersionDefault     = "1.119.0"
	vscodePlatform              = "VSCode"
	vscodeProductName           = "CodeBuddy"
	// 官方 HttpEnvRouteInterceptor：developerMode 关闭时固定 production。
	vscodeEnvID = "production"
)

// chatIdentityProfile 一次 chat 出站按所选身份解析后的覆写面。desktop 为零值
//（不覆写任何头，走既有身份矩阵路径）；cli/vscode 只列与 desktop 的差异。
type chatIdentityProfile struct {
	Identity string // desktop / cli / vscode

	// 通用覆写（cli/vscode 生效）
	UserAgent   string
	IDEName     string // X-IDE-Name
	IDEType     string // X-IDE-Type
	IDEVersion  string // X-IDE-Version
	AgentIntent string // X-Agent-Intent（cli/vscode 均发 craft）
	AgentType   string // X-Agent-Type（main）

	// CLI 专属
	AgentRuntime   string   // X-Agent-Runtime（仅 CLI 非空）
	StainlessOS    string   // x-stainless-os
	StainlessArch  string   // x-stainless-arch
	StainlessNode  string   // x-stainless-runtime-version
	PrivateDataCLI bool     // X-Private-Data：CLI 按企业号 true / 个人号 false
	BodyGzip       bool     // 请求体 gzip + cache_retention=long 注入
	DropFields     []string // CLI 剔除的 body 字段（Responses API / 客户端自定义）

	// VSCode 专属
	ProductVersion         string // X-Product-Version
	EnvID                  string // X-Env-ID
	RequestTraceID         string // X-Request-Trace-Id（带连字符 UUID，每请求新）
	ModelHeaders           bool   // X-Model-ID + monitor_* 毫秒时间戳
	PrivateDataVSCode      bool   // X-Private-Data（官方仅非 CN 站发送）
	PrivateDataVSCodeOmit  bool   // CN 账号：显式不发该头
	NoRootRequestID        bool   // VSCode 主对话不发 X-Root-Request-ID
}

// outboundIdentityFor 解析本次 chat 用哪个出站身份。
// auto = 按 uid 稳定哈希在允许名单内轮换（同账号恒同身份——官方客户端不会一次
// 会话内换 IDE 形态）；名单空/全非法回落 desktop。
func (c *Client) outboundIdentityFor(a *auth.Auth) string {
	if c == nil {
		return OutboundIdentityDesktop
	}
	cfg := c.OutboundIdentity
	if cfg == "" || cfg == OutboundIdentityDesktop {
		return OutboundIdentityDesktop
	}
	if cfg != OutboundIdentityAuto {
		if cfg == OutboundIdentityCLI || cfg == OutboundIdentityVSCode {
			return cfg
		}
		return OutboundIdentityDesktop
	}
	allowed := c.outboundIdentityAllowed()
	if len(allowed) == 0 {
		return OutboundIdentityDesktop
	}
	if len(allowed) == 1 {
		return allowed[0]
	}
	uid := ""
	if a != nil {
		uid = a.UID
	}
	sum := sha256.Sum256([]byte("wb2api-identity:" + uid))
	return allowed[binary.BigEndian.Uint32(sum[:4])%uint32(len(allowed))]
}

// outboundIdentityAllowed 归一化允许名单：保序去重、只留合法身份名。
func (c *Client) outboundIdentityAllowed() []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range c.OutboundIdentityAllowedList {
		switch v {
		case OutboundIdentityDesktop, OutboundIdentityCLI, OutboundIdentityVSCode:
			if !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	return out
}

// cliIDEVersionFor CLI 版本（config upstream.cli_version 覆盖，默认 2.168.2）。
func (c *Client) cliIDEVersionFor() string {
	if c.CLIVersionOverride != "" {
		return c.CLIVersionOverride
	}
	return cliIDEVersionDefault
}

// vscodeIDEVersionFor 宿主 VSCode 版本（官方取 vscode.env；网关无宿主，
// config upstream.vscode_ide_version 覆盖，默认 1.119.0）。
func (c *Client) vscodeIDEVersionFor() string {
	if c.VSCodeIDEVersion != "" {
		return c.VSCodeIDEVersion
	}
	return vscodeIDEVersionDefault
}

// vscodeProductVersionFor 扩展版本（config upstream.vscode_product_version 覆盖）。
func (c *Client) vscodeProductVersionFor() string {
	if c.VSCodeProductVersion != "" {
		return c.VSCodeProductVersion
	}
	return vscodeProductVersionDefault
}

// chatIdentityProfileFor 按所选身份构建 chat 头族覆写面。desktop 返回零值 profile。
func (c *Client) chatIdentityProfileFor(a *auth.Auth) chatIdentityProfile {
	id := c.outboundIdentityFor(a)
	p := chatIdentityProfile{Identity: id}
	switch id {
	case OutboundIdentityCLI:
		ver := c.cliIDEVersionFor()
		p.UserAgent = fmt.Sprintf(cliUAFormat, ver, ver)
		p.IDEName, p.IDEType, p.IDEVersion = "CLI", "CLI", ver
		p.AgentIntent, p.AgentType = agentIntentCraft, agentTypeMain
		p.AgentRuntime = cliAgentRuntime
		p.StainlessOS = stainlessOSValue()
		p.StainlessArch = stainlessArchValue()
		p.StainlessNode = stainlessNodeValue()
		p.PrivateDataCLI = a != nil && a.EnterpriseID != ""
		p.BodyGzip = true
		p.DropFields = []string{"metadata", "conversation_id", "previous_response_id"}
	case OutboundIdentityVSCode:
		p.UserAgent = fmt.Sprintf("%s/%s %s/%s", vscodePlatform, c.vscodeIDEVersionFor(), vscodeProductName, c.vscodeProductVersionFor())
		p.IDEName, p.IDEType = vscodePlatform, vscodePlatform
		p.IDEVersion = c.vscodeIDEVersionFor()
		p.AgentIntent, p.AgentType = agentIntentCraft, agentTypeMain
		p.ProductVersion = c.vscodeProductVersionFor()
		p.EnvID = vscodeEnvID
		p.RequestTraceID = newUUIDHyphenated()
		p.ModelHeaders = true
		if a != nil && a.IsGlobal() {
			p.PrivateDataVSCode = true
		} else {
			p.PrivateDataVSCodeOmit = true
		}
		p.NoRootRequestID = true
	}
	return p
}

// stainlessOSValue / stainlessArchValue / stainlessNodeValue：SDK 本按宿主生成，
// 这里取网关宿主（与 TLS/网络栈一致）；config 可覆盖对齐真实客户端环境。
func stainlessOSValue() string {
	switch runtime.GOOS {
	case "windows":
		return "Windows"
	case "darwin":
		return "MacOS"
	case "linux":
		return "Linux"
	}
	return runtime.GOOS
}

func stainlessArchValue() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x64"
	case "arm64":
		return "arm64"
	case "386":
		return "x32"
	}
	return runtime.GOARCH
}

func stainlessNodeValue() string {
	if v := nodeVersionOverride; v != "" {
		return v
	}
	return "v22.21.1" // 官方 SDK 6.25.0 默认带的 LTS 形态
}

// nodeVersionOverride 由 config 注入（main 启动时设置；测试可改）。
var nodeVersionOverride string

// newUUIDHyphenated 生成带连字符的 UUID（官方 VSCode 拦截器 generateUUUID 形态）。
func newUUIDHyphenated() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strings.Repeat("0", 36)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
