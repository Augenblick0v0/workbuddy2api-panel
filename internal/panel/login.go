// login.go 面板内嵌的 WorkBuddy CN OAuth 设备授权流程（cmd/login 的进程内移植）。
//
//	POST /panel/api/login/start → 拿 state+authUrl，state 存进程内（不再落 /tmp，
//	  原方案在 Windows 上不可用），返回授权 URL；
//	GET  /panel/api/login/poll   → 面板前端每 3s 轮询本接口；未完成返回 done=false，
//	  完成后取 uid/nickname、凭证落盘 auths/workbuddy-<uid>.json、热加载进池
//	  （pool.Add + Revive），并顺带签到 + 余额刷新 —— 免重启加载新账号。
//
// 无 PKCE（workbuddy 设备流由服务端签发 state）。请求身份对齐官方桌面端
//（User-Agent: WorkBuddy/<app>、state 端点 platform=workbuddy|workbuddy-ai、
// X-No-* 声明、authUrl 带 version+loginSessionId），三端点只发
// Content-Type/Accept/User-Agent —— 与可用参照实现（magpie 的
// opencode-workbuddy-auth 插件）逐头一致。
package panel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/egress"
)

const (
	upstreamBaseCN      = "https://copilot.tencent.com"
	upstreamBaseGlobal  = "https://www.workbuddy.ai"
	originRefererCN     = "https://www.codebuddy.cn"
	originRefererGlobal = "https://www.workbuddy.ai"

	// 登录身份对齐官方 **WorkBuddy 桌面端**（证据：magpie 的
	// @magpie-community/opencode-workbuddy-auth 0.2.37 SITES.workbuddy —
	// app=5.9.3 / platform=workbuddy / UA="WorkBuddy/"+app）。
	//
	// 旧实现用 CodeBuddy CLI 身份（UA "CLI/2.63.2 CodeBuddy/2.63.2" +
	// platform=CLI），实测被抓到另一条登录链路：
	//
	//	platform=workbuddy + UA 以 WorkBuddy/ 开头 → https://www.workbuddy.cn/login （WorkBuddy 桌面登录页）
	//	platform=CLI      或 UA 为 CLI/CodeBuddy 形态 → https://copilot.tencent.com/login （CodeBuddy CLI 页）
	//
	// 即用户在面板里点「登录」被送到 CodeBuddy 的页面，拿回来的 state 也不属于
	// WorkBuddy 桌面身份 → 后续 token/account 阶段被上游拒。改用桌面端身份后
	// authUrl 落到 workbuddy.cn，与 magpie 的可用链路一致。
	clientAppVersion = "5.9.3"
	clientUA         = "WorkBuddy/" + clientAppVersion
	platformCN       = "workbuddy"
	platformGlobal   = "workbuddy-ai"
)

// loginEndpoints 按 realm 返回设备授权三端点（auth/state、token、account）+ 品牌 Origin。
// realm=="global" → 国际版（workbuddy.ai 同域 + workbuddy-ai 平台段）；
// cn/非法/缺省 → CN（workbuddy 平台段，零回归兜底）。
func loginEndpoints(realm string) (state, token, account, origin string) {
	if realm == "global" {
		base := upstreamBaseGlobal
		return base + "/v2/plugin/auth/state?platform=" + platformGlobal,
			base + "/v2/plugin/auth/token?state=",
			base + "/v2/plugin/login/account?state=",
			originRefererGlobal
	}
	base := upstreamBaseCN
	return base + "/v2/plugin/auth/state?platform=" + platformCN,
		base + "/v2/plugin/auth/token?state=",
		base + "/v2/plugin/login/account?state=",
		originRefererCN
}

// platformFor 返回该 realm 对应的上游 platform 段（日志/头共用）。
func platformFor(realm string) string {
	if realm == "global" {
		return platformGlobal
	}
	return platformCN
}

// loginHTTP 设备授权专用 client：短超时、无 cookie（每请求携带 state，无会话态）。
var loginHTTP = &http.Client{Timeout: 30 * time.Second}

// commonHeaders 只发官方桌面端那三个头。
//
// 设备授权的三个端点都不是浏览器发起的请求：官方客户端不发 Origin/Referer/
// X-Requested-With（magpie 同样只发 Content-Type/Accept/User-Agent）。旧实现
// 补了 Origin: https://www.codebuddy.cn + X-Requested-With，等于把请求标成
// 「CodeBuddy 网页端」，与桌面端身份自相矛盾。
func commonHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("User-Agent", clientUA)
}

// loginNoIdentityHeaders 是 state 阶段的三段式「别替我注入身份」声明
//（官方桌面端与 magpie 同款）：拿 state 时还没有账号，带上身份头只会让上游
// 按别的产品线派活。
var loginNoIdentityHeaders = map[string]string{
	"X-No-Authorization":   "true",
	"X-No-User-Id":         "true",
	"X-No-Enterprise-Id":   "true",
	"X-No-Department-Info": "true",
}

// loginAccountHeaders 是 account 阶段的头：X-No-Authorization 会让 Bearer 失效，
// 所以只在 state 阶段发；X-No-User-Id / X-No-Enterprise-Id 需与官方一致发出，
// X-Domain 指明令牌所属域（官方取 token.domain，缺省用端点 host）。
func loginAccountHeaders(domain string) map[string]string {
	h := map[string]string{"X-No-User-Id": "true", "X-No-Enterprise-Id": "true"}
	if domain != "" {
		h["X-Domain"] = domain
	}
	return h
}

// loginSessionID 生成 authUrl 的 loginSessionId（官方桌面端为 32 位 hex）。
// CN 登录页会据此建立浏览器侧会话，缺失时企业微信登录入口不出现。
func loginSessionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b[:])
}

// loginAuthURL 给上游返回的授权页补官方参数：version（页面按它决定展示哪些
// 登录方式，CN 版对 version<5.8.0 隐藏企业微信登录）与 loginSessionId。
func loginAuthURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return "", errInvalidAuthURL
	}
	q := u.Query()
	q.Set("version", clientAppVersion)
	q.Set("loginSessionId", loginSessionID())
	u.RawQuery = q.Encode()
	return u.String(), nil
}

var errInvalidAuthURL = errors.New("invalid auth url")

// validUID 校验上游返回的 uid 是否可安全用于拼文件名。
// 只放行字母、数字、下划线、连字符（腾讯侧 uid 实测为 UUID 形态），
// 长度上限 64 兜底异常超长串；拒绝 . / \ 等路径字符与空串。
func validUID(uid string) bool {
	if uid == "" || len(uid) > 64 {
		return false
	}
	for _, c := range uid {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// apiEnvelope 与 upstream 同形：{code,msg,data}，code!=0 视为业务错误。
type apiEnvelope struct {
	Code int             `json:"code"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data"`
}

// loginUpstreamError intentionally does not expose upstream messages or state URLs.
type loginUpstreamError struct {
	status, code int
	pending      bool
	stage        string
	category     string
	transient    bool
	retryAfter   int
}

const (
	loginStageState   = "state"
	loginStageToken   = "token"
	loginStageAccount = "account"
	loginMaxTransient = 5
	loginMaxRetryWait = 60

	// 上游「登录还没完成」的业务码（证据：magpie 的 poll() 重试码表）。
	// token 阶段 11217、account 阶段 12151，官方的 msg 是 "login ing..." 之类
	// 不稳定文案，判定必须以业务码为准。
	loginPendingCodeToken   = 11217
	loginPendingCodeAccount = 12151
)

// loginPending 判断一次业务错误是不是「用户还没在浏览器里完成授权」。
//
// 线上真实响应是 HTTP 200 + {"code":11217,"msg":"login ing..."}（未登录时每
// 3s 都这么回）。旧实现用 msg 白名单匹配（"login ing" 等，不带省略号），真实
// 文案带三个点 → 不匹配 → 被归成 category=business → 前端 app.js 把它翻成
// 「上游拒绝授权」。于是用户刚点登录、甚至还没看清授权页，面板就报失败。
//
// 现在按码判定（与 magpie 一致），msg 只作为老响应形态的兜底。
func loginPending(stage string, env apiEnvelope) bool {
	switch stage {
	case loginStageToken:
		if env.Code == loginPendingCodeToken {
			return true
		}
	case loginStageAccount:
		if env.Code == loginPendingCodeAccount {
			return true
		}
		return false
	}
	// 兼容历史形态：token 阶段的既有「还没登录」文案（含曾经的自述式 msg）
	// 即使码不是 11217 也只算等待 —— 这些文案本来就只出现在 token 阶段。
	switch strings.ToLower(strings.TrimSpace(env.Msg)) {
	case "11217:login ing...":
		// 自带码的旧响应形态：文案与码必须同时对上，避免 999 之类借文案变等待。
		return stage == loginStageToken && env.Code == loginPendingCodeToken
	case "login ing", "login ing...", "pending", "waiting for login", "login pending":
		return stage == loginStageToken
	}
	return false
}

func loginRetryAfter(raw string, now time.Time) int {
	if n, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil {
		if n > 0 {
			return n
		}
		return 0
	}
	if at, err := http.ParseTime(raw); err == nil && at.After(now) {
		return int(math.Ceil(at.Sub(now).Seconds()))
	}
	return 0
}

func loginDiagnostic(e *loginUpstreamError) map[string]any {
	// These fields are enums/integers under our control. Never include err.Error(),
	// upstream msg/body, the full request URL, bearer, or device authorization state.
	return map[string]any{"stage": e.stage, "upstream_status": e.status, "upstream_code": e.code, "category": e.category}
}

func (s *loginSession) stop() {
	s.cancel()
	if s.route != nil {
		s.route.Release()
	}
}

func (p *Panel) credentialLock(uid string) *sync.Mutex {
	p.credentialMu.Lock()
	defer p.credentialMu.Unlock()
	if p.credentialLocks == nil {
		p.credentialLocks = map[string]*sync.Mutex{}
	}
	if p.credentialLocks[uid] == nil {
		p.credentialLocks[uid] = &sync.Mutex{}
	}
	return p.credentialLocks[uid]
}

func (e *loginUpstreamError) Error() string { return "oauth_upstream_failed" }

func (p *Panel) loginEP(realm string) (string, string, string, string) {
	if p.cfg.LoginEndpoints != nil {
		return p.cfg.LoginEndpoints(realm)
	}
	return loginEndpoints(realm)
}

func (p *Panel) loginJSON(ctx context.Context, h *egress.RouteHandle, method, fullURL, bearer string, extra map[string]string, body io.Reader, stage string) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, body)
	if err != nil {
		return nil, &loginUpstreamError{stage: stage, category: "request"}
	}
	commonHeaders(req)
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	client := loginHTTP
	if p.cfg.Egress != nil {
		if err = p.cfg.Egress.CheckCurrent(h); err != nil {
			return nil, err
		}
		req = req.WithContext(egress.WithRoute(req.Context(), h))
		client = &http.Client{Transport: p.cfg.Egress, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, err := client.Do(req)
	if err != nil {
		if p.cfg.Egress != nil {
			var changed *egress.EgressError
			if errors.As(p.cfg.Egress.CheckCurrent(h), &changed) && changed.Code == "oauth_proxy_changed" {
				return nil, changed
			}
		}
		var routeErr *egress.EgressError
		if errors.As(err, &routeErr) {
			if routeErr.Stage == "upstream" && (routeErr.Code == "upstream_timeout" || routeErr.Code == "upstream_transport_failed") {
				return nil, &loginUpstreamError{stage: stage, category: "network", transient: true}
			}
			return nil, routeErr
		}
		var ne net.Error
		transient := (errors.As(err, &ne) && (ne.Timeout() || ne.Temporary())) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
		return nil, &loginUpstreamError{stage: stage, category: "network", transient: transient}
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		retryAfter := loginRetryAfter(resp.Header.Get("Retry-After"), time.Now())
		transient := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 && resp.StatusCode <= 599
		// Do not retry sooner than requested, or keep a session in an unbounded wait.
		if retryAfter > loginMaxRetryWait {
			transient = false
		}
		return nil, &loginUpstreamError{stage: stage, category: "http", status: resp.StatusCode, transient: transient, retryAfter: retryAfter}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return nil, &loginUpstreamError{stage: stage, category: "response", status: resp.StatusCode, transient: err != nil}
	}
	var env apiEnvelope
	if json.Unmarshal(raw, &env) != nil {
		return nil, &loginUpstreamError{stage: stage, category: "response", status: resp.StatusCode}
	}
	if env.Code != 0 {
		return nil, &loginUpstreamError{stage: stage, category: "business", status: resp.StatusCode, code: env.Code, pending: loginPending(stage, env)}
	}
	return env.Data, nil
}

func (p *Panel) loginAccess(w http.ResponseWriter, r *http.Request) bool {
	if p.cfg.Egress == nil {
		return true
	}
	allowed := false
	// OAuth polling writes credentials even though the legacy verb is GET.
	copyReq := r.Clone(r.Context())
	copyReq.Method = http.MethodPost
	p.proxyAdmin(func(http.ResponseWriter, *http.Request) { allowed = true })(w, copyReq)
	return allowed
}

func (p *Panel) loginStart(w http.ResponseWriter, r *http.Request) {
	if !p.loginAccess(w, r) {
		return
	}
	var in struct {
		Realm   string `json:"realm"`
		SlotID  string `json:"proxy_slot_id"`
		Confirm bool   `json:"confirm_rebind"`
	}
	if r.Body != nil {
		if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&in); err != nil && err != io.EOF {
			proxyError(w, 400, "invalid_login_request")
			return
		}
	}
	realm := "cn"
	if in.Realm == "global" {
		realm = "global"
	}
	var h *egress.RouteHandle
	if p.cfg.Egress != nil {
		var err error
		h, err = p.cfg.Egress.ResolveSlot(in.SlotID)
		if err != nil {
			proxyFailure(w, err)
			return
		}
	}
	keep := false
	defer func() {
		if !keep && h != nil {
			h.Release()
		}
	}()
	ep, _, _, _ := p.loginEP(realm)
	data, err := p.loginJSON(r.Context(), h, http.MethodPost, ep, "", loginNoIdentityHeaders, bytes.NewReader([]byte("{}")), loginStageState)
	if err != nil {
		p.loginFailure(w, err)
		return
	}
	var st struct {
		State   string `json:"state"`
		AuthURL string `json:"authUrl"`
	}
	if json.Unmarshal(data, &st) != nil || st.State == "" || len(st.State) > 4096 {
		proxyError(w, 502, "oauth_state_failed")
		return
	}
	authURL, err := loginAuthURL(st.AuthURL)
	if err != nil {
		proxyError(w, 502, "oauth_url_failed")
		return
	}
	st.AuthURL = authURL
	ctx, cancel := context.WithTimeout(context.Background(), loginTTL)
	sess := &loginSession{created: time.Now(), realm: realm, ctx: ctx, cancel: cancel, route: h, confirmRebind: in.Confirm}
	if h != nil {
		context.AfterFunc(ctx, h.Release)
	}
	p.loginMu.Lock()
	for state, old := range p.logins {
		if time.Since(old.created) > loginTTL {
			old.stop()
			delete(p.logins, state)
		}
	}
	if len(p.logins) >= 1024 {
		p.loginMu.Unlock()
		cancel()
		proxyError(w, 503, "oauth_session_limit")
		return
	}
	if old := p.logins[st.State]; old != nil {
		p.loginMu.Unlock()
		cancel()
		proxyError(w, 502, "oauth_state_collision")
		return
	}
	p.logins[st.State] = sess
	p.loginMu.Unlock()
	keep = true
	log.Printf("panel: OAuth started realm=%s platform=%s app=%s", realm, platformFor(realm), clientAppVersion)
	writeJSON(w, 200, map[string]any{"ok": true, "url": st.AuthURL, "state": st.State, "realm": realm, "proxy_slot_id": in.SlotID})
}

func (p *Panel) loginFailure(w http.ResponseWriter, err error) {
	var ee *egress.EgressError
	if errors.As(err, &ee) {
		proxyFailure(w, err)
		return
	}
	var oe *loginUpstreamError
	if errors.As(err, &oe) {
		d := loginDiagnostic(oe)
		d["error"], d["code"] = "oauth_upstream_failed", "oauth_upstream_failed"
		writeJSON(w, 502, d)
		return
	}
	proxyError(w, 502, "oauth_upstream_failed")
}

func (p *Panel) loginPoll(w http.ResponseWriter, r *http.Request) {
	if !p.loginAccess(w, r) {
		return
	}
	state := r.URL.Query().Get("state")
	p.loginMu.Lock()
	sess := p.logins[state]
	p.loginMu.Unlock()
	if state == "" {
		proxyError(w, 400, "missing_state")
		return
	}
	if sess == nil {
		proxyError(w, 404, "oauth_unknown_state")
		return
	}
	if !sess.mu.TryLock() {
		writeJSON(w, 200, map[string]any{"done": false, "message": "poll_in_progress"})
		return
	}
	defer sess.mu.Unlock()
	if sess.result != nil {
		writeJSON(w, 200, sess.result)
		return
	}
	if sess.stopped != "" {
		proxyError(w, 409, sess.stopped)
		return
	}
	terminal := func(code string) { sess.stopped = code; sess.stop() }
	if sess.ctx.Err() != nil {
		terminal("oauth_expired")
		proxyError(w, 409, "oauth_expired")
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(sess.ctx, cancel)
	defer cancel()
	defer stop()
	if p.cfg.Egress != nil {
		if err := p.cfg.Egress.CheckCurrent(sess.route); err != nil {
			terminal("oauth_proxy_changed")
			p.loginFailure(w, err)
			return
		}
	}
	_, epToken, epAcct, _ := p.loginEP(sess.realm)
	if sess.credentials == nil {
		if time.Now().Before(sess.nextPollAt) {
			retry := int(math.Ceil(time.Until(sess.nextPollAt).Seconds()))
			w.Header().Set("Retry-After", strconv.Itoa(retry))
			writeJSON(w, 200, map[string]any{"done": false, "message": "upstream_retry_wait", "retry_after": retry, "stage": loginStageToken, "category": "retry_wait"})
			return
		}
		raw, err := p.loginJSON(ctx, sess.route, http.MethodGet, epToken+url.QueryEscape(state), "", nil, nil, loginStageToken)
		if err != nil {
			var oe *loginUpstreamError
			if errors.As(err, &oe) && oe.pending {
				sess.transientFailures, sess.nextPollAt = 0, time.Time{}
				d := loginDiagnostic(oe)
				d["done"], d["message"], d["retry_after"] = false, "waiting_for_login", 3
				writeJSON(w, 200, d)
				return
			}
			if ctx.Err() != nil {
				if sess.ctx.Err() != nil {
					terminal("oauth_expired")
					proxyError(w, 409, "oauth_expired")
				} else {
					// A disconnected poll client must not destroy the user's authorization.
					proxyError(w, 409, "oauth_poll_cancelled")
				}
				return
			}
			if errors.As(err, &oe) && oe.transient && sess.transientFailures < loginMaxTransient {
				retry := 3 << sess.transientFailures
				if oe.retryAfter > retry {
					retry = oe.retryAfter
				}
				if retry > loginMaxRetryWait {
					retry = loginMaxRetryWait
				}
				if deadline, ok := sess.ctx.Deadline(); ok && time.Until(deadline) <= time.Duration(retry)*time.Second {
					terminal("oauth_expired")
					proxyError(w, 409, "oauth_expired")
					return
				}
				sess.transientFailures++
				sess.nextPollAt = time.Now().Add(time.Duration(retry) * time.Second)
				d := loginDiagnostic(oe)
				d["done"], d["message"], d["retry_after"] = false, "upstream_retry_wait", retry
				w.Header().Set("Retry-After", strconv.Itoa(retry))
				writeJSON(w, 200, d)
				return
			}
			terminal("oauth_terminal_error")
			p.loginFailure(w, err)
			return
		}
		sess.transientFailures, sess.nextPollAt = 0, time.Time{}
		var tok struct {
			AccessToken  string `json:"accessToken"`
			RefreshToken string `json:"refreshToken"`
			ExpiresIn    int64  `json:"expiresIn"`
			Domain       string `json:"domain"`
		}
		if json.Unmarshal(raw, &tok) != nil || tok.AccessToken == "" {
			terminal("oauth_token_failed")
			proxyError(w, 502, "oauth_token_failed")
			return
		}
		// X-Domain：官方取 token.domain，缺省用 account 端点 host（与 magpie 同）。
		domain := strings.TrimSpace(tok.Domain)
		if domain == "" {
			if u, uerr := url.Parse(epAcct); uerr == nil {
				domain = u.Host
			}
		}
		raw, err = p.loginJSON(ctx, sess.route, http.MethodGet, epAcct+url.QueryEscape(state), tok.AccessToken, loginAccountHeaders(domain), nil, loginStageAccount)
		if err != nil {
			var oe *loginUpstreamError
			// state 已授权、令牌也拿到了，但账号信息还没落定（12151）→ 继续等，
			// 不能把会话判死（旧实现直接 terminal，用户只能重来一遍授权）。
			if errors.As(err, &oe) && oe.pending {
				sess.transientFailures, sess.nextPollAt = 0, time.Time{}
				d := loginDiagnostic(oe)
				d["done"], d["message"], d["retry_after"] = false, "waiting_for_login", 3
				writeJSON(w, 200, d)
				return
			}
			terminal("oauth_terminal_error")
			p.loginFailure(w, err)
			return
		}
		var acct struct {
			UID          string `json:"uid"`
			Nickname     string `json:"nickname"`
			EnterpriseID string `json:"enterpriseId"`
		}
		if json.Unmarshal(raw, &acct) != nil || !validUID(acct.UID) {
			terminal("oauth_account_failed")
			proxyError(w, 502, "oauth_account_failed")
			return
		}
		if tok.ExpiresIn <= 0 || tok.ExpiresIn > 10*365*86400 {
			tok.ExpiresIn = 3600
		}
		a := &auth.Auth{AccessToken: tok.AccessToken, RefreshToken: tok.RefreshToken, ExpiresAt: time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).Unix(), Domain: tok.Domain, UID: acct.UID, Nickname: acct.Nickname, EnterpriseID: acct.EnterpriseID, FilePath: filepath.Join(p.cfg.AuthDir, "workbuddy-"+acct.UID+".json")}
		if _, err = auth.BackfillRealmFor(a, sess.realm); err != nil {
			terminal("oauth_account_failed")
			proxyError(w, 502, "oauth_account_failed")
			return
		}
		sess.credentials = a
	}
	a := sess.credentials
	uidLock := p.credentialLock(a.UID)
	uidLock.Lock()
	defer uidLock.Unlock()
	if ctx.Err() != nil {
		terminal("oauth_cancelled")
		proxyError(w, 409, "oauth_cancelled")
		return
	}
	var existing *auth.Auth
	if p.cfg.Pool != nil {
		existing = p.cfg.Pool.AuthByUID(a.UID)
	}
	confirm := sess.confirmRebind || r.URL.Query().Get("confirm_rebind") == "true"
	if p.cfg.Egress != nil {
		if err := p.cfg.Egress.CheckCurrent(sess.route); err != nil {
			terminal("oauth_proxy_changed")
			p.loginFailure(w, err)
			return
		}
		// One CAS transaction checks the pinned generation and persists binding before
		// any credential write or Pool.Add. Never invoke Manager methods inside edit.
		for {
			snap := p.cfg.Egress.Snapshot()
			prior, assigned := snap.Bindings[a.UID]
			if (assigned || existing != nil) && prior != sess.route.SlotID && !confirm {
				proxyError(w, 409, "oauth_rebind_required")
				return
			}
			_, err := p.cfg.Egress.Update(snap.Revision, func(c *egress.Config) error {
				if sess.route.SlotID != "" {
					slot, ok := c.Slots[sess.route.SlotID]
					if !ok || !slot.Enabled || slot.TransportGeneration != sess.route.Generation {
						return &egress.EgressError{Code: "oauth_proxy_changed", SlotID: sess.route.SlotID, Stage: "oauth_bind"}
					}
				}
				old, exists := c.Bindings[a.UID]
				if (exists || existing != nil) && old != sess.route.SlotID && !confirm {
					return &egress.EgressError{Code: "oauth_rebind_required", Stage: "oauth_bind"}
				}
				c.Bindings[a.UID] = sess.route.SlotID
				if c.PendingAccounts == nil {
					c.PendingAccounts = map[string]bool{}
				}
				c.PendingAccounts[a.UID] = true
				return nil
			})
			var ee *egress.EgressError
			if errors.As(err, &ee) && ee.Code == "revision_conflict" {
				continue
			}
			if err != nil {
				terminal("oauth_binding_failed")
				p.loginFailure(w, err)
				return
			}
			break
		}
	}
	if ctx.Err() != nil {
		terminal("oauth_cancelled")
		proxyError(w, 409, "oauth_cancelled")
		return
	}
	if p.cfg.Egress != nil {
		if err := p.cfg.Egress.CheckCurrent(sess.route); err != nil {
			terminal("oauth_proxy_changed")
			p.loginFailure(w, err)
			return
		}
	}
	if err := os.MkdirAll(p.cfg.AuthDir, 0700); err != nil {
		terminal("oauth_credentials_failed")
		proxyError(w, 500, "oauth_credentials_failed")
		return
	}
	if existing != nil {
		if err := existing.ReplaceCredentials(a); err != nil {
			terminal("oauth_credentials_failed")
			proxyError(w, 500, "oauth_credentials_failed")
			return
		}
		a = existing
	} else if err := a.SaveAtomic(); err != nil {
		terminal("oauth_credentials_failed")
		proxyError(w, 500, "oauth_credentials_failed")
		return
	}
	if p.cfg.Egress != nil {
		// A durable transition guard also blocks an existing UID's old token
		// during the bind->credential window and survives a failed write/restart.
		for {
			snap := p.cfg.Egress.Snapshot()
			_, err := p.cfg.Egress.Update(snap.Revision, func(c *egress.Config) error {
				if ctx.Err() != nil || c.Bindings[a.UID] != sess.route.SlotID {
					return &egress.EgressError{Code: "oauth_proxy_changed", Stage: "oauth_finalize"}
				}
				if sess.route.SlotID != "" {
					slot, ok := c.Slots[sess.route.SlotID]
					if !ok || !slot.Enabled || slot.TransportGeneration != sess.route.Generation {
						return &egress.EgressError{Code: "oauth_proxy_changed", Stage: "oauth_finalize"}
					}
				}
				delete(c.PendingAccounts, a.UID)
				return nil
			})
			var ee *egress.EgressError
			if errors.As(err, &ee) && ee.Code == "revision_conflict" {
				continue
			}
			if err != nil {
				terminal("oauth_commit_failed")
				p.loginFailure(w, err)
				return
			}
			break
		}
	}
	if p.cfg.Pool != nil {
		p.cfg.Pool.Add(a)
		p.cfg.Pool.Revive(a.UID)
	}
	up := p.cfg.Upstream
	if up != nil && p.cfg.Egress != nil {
		up = up.ForRoute(sess.route)
	}
	checkinMsg := ""
	remain := int64(-1)
	total := int64(0)
	if up != nil {
		stopped := false
		note := func(err error) {
			if err != nil {
				checkinMsg = joinMsg(checkinMsg, err.Error())
				var ee *egress.EgressError
				if errors.As(err, &ee) {
					stopped = true
				}
			}
		}
		if sess.realm == "global" {
			_, err := up.GlobalCompleteRegistration(a)
			note(err)
			if !stopped {
				_, err = up.ClaimTrial(a)
				note(err)
			}
		} else if !a.IsEnterprise() {
			note(up.DailyCheckin(a))
		}
		if !stopped {
			if rm, tt, err := up.UserResource(a); err == nil {
				remain, total = rm, tt
				if p.cfg.Pool != nil {
					p.cfg.Pool.ReenableIfCredits(a.UID, rm, tt)
				}
			} else {
				note(err)
			}
		}
	}
	sess.result = map[string]any{"done": true, "uid": a.UID, "nickname": a.Nickname, "realm": sess.realm, "credits": remain, "credits_total": total, "checkin_message": checkinMsg}
	sess.credentials = nil
	sess.stop()
	log.Printf("panel: OAuth account loaded uid=%s realm=%s", a.UID, sess.realm)
	writeJSON(w, 200, sess.result)
}

func (p *Panel) loginCancel(w http.ResponseWriter, r *http.Request) {
	if !p.loginAccess(w, r) {
		return
	}
	var in struct {
		State string `json:"state"`
	}
	if !proxyDecode(w, r, &in) {
		return
	}
	p.loginMu.Lock()
	sess := p.logins[in.State]
	delete(p.logins, in.State)
	p.loginMu.Unlock()
	if sess != nil {
		sess.stop()
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// joinMsg 拼接 login 完成后的提示消息（多段用「；」连接，空段跳过）。
func joinMsg(parts ...string) string {
	out := ""
	for _, s := range parts {
		if s == "" {
			continue
		}
		if out != "" {
			out += "；"
		}
		out += s
	}
	return out
}

// loginRegions 返回 global 注册可选地区（panel 前端选地区弹窗用；CN 不调用）。
// 未持账号时返回白名单静态兜底（前端只读展示，不依赖上游）。
func (p *Panel) loginRegions(w http.ResponseWriter, r *http.Request) {
	// 静态白名单（对齐国际版 web 展示集）：面板前端只读展示，无需账号态。
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"regions": []map[string]string{
			{"code": "HK", "name": "Hong Kong"},
			{"code": "MO", "name": "Macao"},
			{"code": "SG", "name": "Singapore"},
			{"code": "TH", "name": "Thailand"},
			{"code": "PH", "name": "Philippines"},
			{"code": "MY", "name": "Malaysia"},
			{"code": "ID", "name": "Indonesia"},
		},
	})
}
