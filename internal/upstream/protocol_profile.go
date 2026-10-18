package upstream

import "github.com/linguo2625469/workbuddy2api-panel/internal/auth"

// ─────────────────────────────────────────────────────────────────────────────
// 身份矩阵（identity matrix）
//
// 本文件是全仓**唯一**允许出现「客户端出站身份」字面量的地方：客户端 / CLI 版本号、
// UA 品牌段、IDE 名称与类型、产品名、Origin / Referer / 语言、X-Agent-* 取值。
// 其它非测试 .go 文件（headers.go / desktop.go / school.go / global_models.go …）
// 一律引用 desktopSpec / mpSpec 解析后的结果，不得再自带这些字面量（规格 §2）。
//
// 取值证据（完整表见 docs/identity-upgrade.md）：
//
//	E1  2026-10-16 Hub mitmproxy 抓到国际版桌面端 5.8.4 出站：
//	    UA `WorkBuddy/5.8.4 workbuddy-ai/5.8.4 CLI/2.161.0`、X-IDE-Version 5.8.4、
//	    X-Agent-Intent=craft / X-Agent-Type=main / X-Agent-Purpose=conversation、
//	    X-Private-Data=true、X-Domain=www.workbuddy.ai、X-Product=SaaS。
//	    （注意：Electron 主进程 sidecar 的 `workbuddy-ai/...` 双段 UA 属于另一条链路，
//	    不是此处要仿的 RestOperations 层形状，不复制。）
//	E2  2026-10-18 直连 /v3/config 对比实测：global 账号平台段送 `workbuddy-ai` 与
//	    `WorkBuddy AI` 均返回 HTTP 200 code=0 —— 旧注释里「送错平台段会 403 code 11140」
//	    的结论已被证伪；且 5.5.4→5.5.6 / 5.8.4 的版本与 UA 变更**不改变模型目录**
//	    （CN 60 个、global 27 个、差异集为空）→ 升级 UA 品牌段与版本无功能风险。
//	E3  CN 侧本次无新抓包：保持 2026-09 实测值（客户端 5.5.6 / CLI 2.137.1 / 品牌段
//	    `WorkBuddy` / 头族完全不变）零漂移；对 CN 的唯一改动是把内置默认客户端版本
//	    从 5.5.4 对齐到实测的 5.5.6。
//
// ─────────────────────────────────────────────────────────────────────────────
const (
	// 身份名：仅用于诊断与文档标注，不参与线上报文。
	identityDesktop = "workbuddy-desktop"
	identityMP      = "workbuddy-mp"

	realmCN     = "cn"
	realmGlobal = "global"

	originRefererCN     = "https://www.codebuddy.cn"
	originRefererGlobal = "https://www.workbuddy.ai"

	// 客户端版本：CN 取 E3 实测值，global 取 E1 实测值。
	desktopClientVersionCN     = "5.5.6"
	desktopClientVersionGlobal = "5.8.4"
	desktopCLIVersionCN        = "2.137.1"
	desktopCLIVersionGlobal    = "2.161.0"
	// 小程序端版本：ideVersion / extVersion / X-Client-Version 同值（2026-09 实测）。
	mpClientVersion = "2.4.0"

	// UA 第二段（品牌段）：CN 与 applicationName 同值；global 用国际版 productName
	// （E1 抓包实测 `workbuddy-ai`；E2 证明它与旧的 `WorkBuddy AI` 等价可用）。
	brandSegmentCN     = "WorkBuddy"
	brandSegmentGlobal = "workbuddy-ai"

	ideNameDesktop = "WorkBuddy"
	ideTypeDesktop = "WorkBuddy"
	ideNameMP      = "wx_app_cloud"
	ideTypeMP      = "WorkBuddy_MP"
	productSaaS    = "SaaS"

	// X-Agent-* 取值：CN 只发 purpose（既有零漂移形态）；global 另发 intent/type。
	agentPurposeConversation = "conversation"
	agentIntentCraft         = "craft"
	agentTypeMain            = "main"

	// 桌面端本地任务链路（/v2/report 事件链 + DesktopChatWithExpert）历史一直发送的
	// X-Agent-* 取值：CN 与 global 都发 craft/main（E3：CN 实测形态，保持零漂移）。
	desktopTaskAgentIntent = "craft"
	desktopTaskAgentType   = "main"

	// UA 形状：`WorkBuddy/<ver> <brand>/<ver> CLI/<cli>`（官方 RestOperations 层）。
	uaProductPrefix = "WorkBuddy/"
	uaCLISeparator  = " CLI/"

	languageCN     = "zh-CN"
	languageGlobal = "en-US"
)

// identitySpec 是「桌面端身份」在某个 realm 下解析后的完整取值。
// 只含出站报文身份字段，不含凭据、设备标识或每请求可变状态。
type identitySpec struct {
	Realm         string // realmCN / realmGlobal
	Identity      string // identityDesktop
	ClientVersion string // 生效客户端版本（config 覆盖后）
	CLIVersion    string // 生效 CLI 版本（config 覆盖后）
	BrandSegment  string // UA 第二段品牌
	IdeName       string // X-IDE-Name
	IdeType       string // X-IDE-Type
	UserAgent     string // 最终出站 UA（含 config user_agent 覆盖）
	Origin        string
	Referer       string
	Language      string
	Product       string // X-Product
	AgentIntent   string // global 才非空（CN 不发送该头）
	AgentPurpose  string
	AgentType     string // global 才非空（CN 不发送该头）
	PrivateData   bool   // global 才为 true（X-Private-Data，E1）
}

// mpIdentitySpec 小程序端身份：无 UA、无 Origin/Referer（MP 上报只带 body 指纹
// 与 X-Client-* 头，历史抓包从未出现 UA 头，故这里不给 UA 字段）。
type mpIdentitySpec struct {
	Realm         string
	Identity      string
	ClientVersion string // ideVersion / extVersion / X-Client-Version
	IdeName       string
	IdeType       string
	Product       string
}

// desktopUAShape 组装官方桌面端三段式 UA。
func desktopUAShape(clientVersion, brandSegment, cliVersion string) string {
	return uaProductPrefix + clientVersion + " " + brandSegment + "/" + clientVersion + uaCLISeparator + cliVersion
}

// desktopSpecBase 解析桌面端身份矩阵默认值 + config 版本覆盖，但**不含** UA 整段覆盖。
// 需要「官方默认 UA」的调用方（如模型目录探测的三探针主路）用它；其它路径用 desktopSpec。
func (c *Client) desktopSpecBase(a *auth.Auth) identitySpec {
	spec := identitySpec{
		Realm: realmCN, Identity: identityDesktop,
		ClientVersion: desktopClientVersionCN, CLIVersion: desktopCLIVersionCN,
		BrandSegment: brandSegmentCN,
		IdeName:      ideNameDesktop, IdeType: ideTypeDesktop,
		Origin: originRefererCN, Language: languageCN, Product: productSaaS,
		AgentPurpose: agentPurposeConversation,
	}
	if a != nil && a.IsGlobal() {
		spec.Realm = realmGlobal
		spec.ClientVersion, spec.CLIVersion = desktopClientVersionGlobal, desktopCLIVersionGlobal
		spec.BrandSegment = brandSegmentGlobal
		spec.Origin, spec.Language = originRefererGlobal, languageGlobal
		// E1：国际版桌面端 5.8.4 抓包出现的三个归属头 + 私有数据声明。
		spec.AgentIntent, spec.AgentType, spec.PrivateData = agentIntentCraft, agentTypeMain, true
	}
	// 显式 config 覆盖矩阵默认（规格 §2：config 优先，且同时影响 UA 两段版本 +
	// X-IDE-Version + 上报 body 的 ideVersion/extVersion + billing 短 UA）。
	if c != nil && c.ClientVersion != "" {
		spec.ClientVersion = c.ClientVersion
	}
	if c != nil && c.CliVersion != "" {
		spec.CLIVersion = c.CliVersion
	}
	spec.Referer = spec.Origin + "/"
	spec.UserAgent = desktopUAShape(spec.ClientVersion, spec.BrandSegment, spec.CLIVersion)
	return spec
}

// desktopSpec 生效桌面端身份：矩阵默认 + config 覆盖（user_agent 整段覆盖 UA）。
func (c *Client) desktopSpec(a *auth.Auth) identitySpec {
	spec := c.desktopSpecBase(a)
	// 显式 user_agent 覆盖整段 UA（品牌段/版本段都不再生效，保留既有兼容语义）。
	if c != nil && c.UserAgent != "" {
		spec.UserAgent = c.UserAgent
	}
	return spec
}

// mpSpec 生效小程序端身份。MP 上报固定在 CN 域（www.codebuddy.cn），无 realm 分支。
func (c *Client) mpSpec(a *auth.Auth) mpIdentitySpec {
	spec := mpIdentitySpec{
		Realm: realmCN, Identity: identityMP,
		ClientVersion: mpClientVersion,
		IdeName:       ideNameMP, IdeType: ideTypeMP, Product: productSaaS,
	}
	// 注意：小程序端版本**不**跟随 client_version 覆盖——升级前 mpEventBase 就是
	// 硬编码 2.4.0，与桌面端版本无关；跟随覆盖属规格外的新行为（规格 §3 只要求
	// 「ideVersion/extVersion/X-Client-Version = 2.4.0 不变」），故保持零漂移。
	return spec
}

// resolvedProtocol 描述按 realm × purpose 解析出的既有出站行为。
// 不含凭据、设备标识或每请求可变状态。
type resolvedProtocol struct {
	Realm, Purpose, UserAgent, ClientVersion, CLIVersion, ClientName string
	Origin, Referer, Language, Product                               string
	Identity, IdeName, IdeType, AgentIntent, AgentPurpose, AgentType string
	PrivateData                                                      bool
	MachineHeader, SessionHeader                                     bool
}

// protocolFor 解析某个 purpose 的出站协议画像。桌面端身份全部来自身份矩阵
// （global 账号自动切 5.8.4 / workbuddy-ai / en-US / 国际版域，CN 保持既有取值）。
//
// purpose 语义：
//   - billing / task_billing：白名单类（billing/checkin/banner/report），不注入
//     Origin/Referer 与 X-Machine-ID/X-Session-ID，UA 退化为单段短形态；
//   - 其它（chat/common/refresh/models）：完整官方桌面端形态。
func (c *Client) protocolFor(a *auth.Auth, purpose string) resolvedProtocol {
	spec := c.desktopSpecBase(a)
	p := resolvedProtocol{
		Realm: spec.Realm, Purpose: purpose,
		ClientVersion: spec.ClientVersion, CLIVersion: spec.CLIVersion,
		ClientName: c.attributionClientName(),
		Origin:     spec.Origin, Referer: spec.Referer, Language: spec.Language,
		Identity: spec.Identity, IdeName: spec.IdeName, IdeType: spec.IdeType,
		AgentIntent: spec.AgentIntent, AgentPurpose: spec.AgentPurpose,
		AgentType: spec.AgentType, PrivateData: spec.PrivateData,
		UserAgent: spec.UserAgent, MachineHeader: true, SessionHeader: true,
	}
	if purpose == "billing" || purpose == "task_billing" {
		p.MachineHeader, p.SessionHeader = false, false
		p.Origin, p.Referer = "", ""
		p.UserAgent = c.billingUAFor(a)
	} else if purpose == "chat" {
		// 归属名（X-Product）：CN 跟随 client_name（默认 WorkBuddy），
		// global 固定 SaaS（E1 抓包；国际版客户端不发 client_name 品牌）。
		if spec.Realm == realmGlobal {
			p.Product = spec.Product
		} else {
			p.Product = p.ClientName
		}
	}
	// 显式 user_agent 覆盖整段 UA（既有兼容语义，所有 purpose 一致生效）。
	if c != nil && c.UserAgent != "" {
		p.UserAgent = c.UserAgent
	}
	return p
}
