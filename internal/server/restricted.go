// restricted.go 风控 11140（unusual activity 形态）连坐保护状态机。
//
// 背景（社区复盘红线，Hub 5e1eb51 同源）：上游对国际账号回 403 / code 11140
//（'account restricted due to unusual activity'）时，同设备指纹的账号会被连坐
// ——继续换号重试等于把整池账号逐个送上去（#422：一次任务 7 个号全没）。
// 本状态机是这条红线的代码化：
//   - 单次命中：handler 立即终止轮转（不换号），账号长冷却（applyErrorPolicy）；
//   - 波形判定：restrictedWindow（15min 滑动窗）内 ≥ restrictedThreshold 个
//     **不同** UID 命中 → 判定风控波形，整域池暂停 restrictedHold（30min）：
//     该 realm 全部账号冷却到 now+30m（跳过已在更长冷却中的号，不缩短既有
//     惩罚）。单号反复命中（重试风暴）只计 1 个号，不触发整池暂停。
//
// 归属 server（Handler 局部）而非 pool：跨 UID 的波形语义与 wafip.go 的 IP 级
// 闸门同型；进程内状态、重启清零（窗 15min，重建成本低）。账号级长冷却照常
// 走 pool 记账（持久化随既有冷却状态）。
package server

import (
	"log"
	"sync"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
)

// restrictedWindow 波形判定滑动窗（Hub 默认 900s）。
var restrictedWindow = 15 * time.Minute

// restrictedThreshold 窗内不同 UID 命中数阈值（Hub 默认 2：两号已构成连坐证据）。
const restrictedThreshold = 2

// restrictedHold 整域池暂停时长（Hub 默认 1800s；0 语义上关闭——这里恒 >0）。
var restrictedHold = 30 * time.Minute

// restrictedGate 风控波形状态机（Handler 内嵌，零值可用）。
type restrictedGate struct {
	mu   sync.Mutex
	hits map[string]time.Time // uid → 窗内最近一次命中（惰性剪枝）
}

// noteRestricted 记一次某账号的风控 11140 命中。返回波形是否激活（首次激活时
// 已对整域池执行冷却；调用方无论返回值都应终止轮转——单号命中本身就不换号）。
// pauseRealm 为波形激活时对整域执行暂停的回调（传入 pool 与 realm）。
func (g *restrictedGate) noteRestricted(uid, realm string, pauseRealm func()) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if g.hits == nil {
		g.hits = map[string]time.Time{}
	}
	g.hits[uid] = now
	distinct := 0
	for u, at := range g.hits {
		if now.Sub(at) > restrictedWindow {
			delete(g.hits, u)
			continue
		}
		distinct++
	}
	if distinct < restrictedThreshold {
		return false
	}
	// 波形激活：整域池暂停（调用方执行，含「不缩短更长冷却」保护），并清空
	// 窗口（暂停期内不重复触发、不计新波形）。
	g.hits = map[string]time.Time{}
	if pauseRealm != nil {
		pauseRealm()
	}
	return true
}

// pauseRealmCooldowns 整域池暂停：realm 内全部账号冷却到 now+restrictedHold。
// 已在更长冷却中的号跳过（不缩短既有惩罚——风控长冷却 2h 不被 30m 暂停覆盖）。
// disabled/paused 账号不动（本来就不参与选号）。
func (h *Handler) pauseRealmCooldowns(realm string) {
	if h.cfg.Pool == nil {
		return
	}
	paused := 0
	for _, st := range h.cfg.Pool.List() {
		if st.Realm != realm || st.Disabled || st.Paused {
			continue
		}
		if st.Cooling && st.Until.After(time.Now().Add(restrictedHold)) {
			continue
		}
		h.cfg.Pool.Cooldown(st.UID, pool.CoolHard, restrictedHold, "risk-control wave pause (11140)")
		paused++
	}
	log.Printf("WARN: [server] risk-control 11140 wave: realm=%s pool paused %dm (%d accounts cooled)",
		realm, int(restrictedHold.Minutes()), paused)
}
