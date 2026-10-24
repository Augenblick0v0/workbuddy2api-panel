// quota_scan.go 模型额度窗口复验扫描（Hub quota-scan 的窗口探针子集）。
//
// 范围刻意收窄：只处理**已在限流台账上**的 (账号, 模型) 线——它们带着上游给的
// 重置墙钟（ResetAt）。扫描器在窗口到期前发一次 1-token 探针复验：
//   - 探针 200 → 该配额线已重开，立即 BlockModelClear 解除模型冷却（抢占新窗口，
//     不必等截断的 Until 自然到期——soft_rate_max 截断过的窗口可能比真实重置
//     晚很久，白等 = 白扔可用额度）；
//   - 探针 429 → 窗口未开：按新解析的重置时间续窗（CooldownSoftForModel），无
//     解析时间则保持现状（下一周期再验）；
//   - 其它错误 → 记日志跳过（不罚账号：探针失败不是账号的错）。
//
// 主动「全池逐模型扫描」（Hub 的完整 quota-scan）不做：那是每个 (账号, 模型)
// 组合每周期一次真实请求，配额消耗可观；本网关的窗口知识由真实流量的 429 解析
// 获得（已持久化），扫描只负责「到点复验 + 提前解锁」。因此缺省关闭
//（schedule.quota_scan_enabled=false，探针花真实配额，由运维显式开启）。
package scheduler

import (
	"context"
	"log"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/logfmt"
	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

// quotaScanLead 窗口到期前的提前复验窗口：ResetAt 落在「现在 ~ 现在+lead」内的
// 限流线本轮会被探针复验。
const quotaScanLead = 3 * time.Minute

// quotaScanExtendBase 续窗时的退避基数：仅当 resetAt 缺失才生效（本路径恒带
// resetAt，此值实际不被消费，取与 soft_rate 同量级的保守值）。
const quotaScanExtendBase = 10 * time.Minute

// StartQuotaWindowScan 周期扫描限流台账并复验临近到期的窗口。
func (s *Scheduler) StartQuotaWindowScan(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		log.Printf("scheduler: 模型额度窗口复验每 %s（lead %s）", interval, quotaScanLead)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.scanQuotaWindows()
			}
		}
	}()
}

// scanQuotaWindows 一轮复验：遍历限流台账，临近/已过 ResetAt 的线发 1-token 探针。
func (s *Scheduler) scanQuotaWindows() {
	now := time.Now()
	for _, st := range s.cfg.Pool.List() {
		if st.Disabled {
			continue
		}
		for _, m := range st.RateLimitedModels {
			resetAt := m.ResetAt
			if resetAt.IsZero() {
				resetAt = m.Until
			}
			if resetAt.IsZero() {
				continue
			}
			// 只复验「已到期或 lead 内到期」的线：早于窗口的探针只会再吃一个 429。
			if now.Add(quotaScanLead).Before(resetAt) {
				continue
			}
			s.probeQuotaLine(st.UID, st.Nickname, m.Model)
		}
	}
}

// probeQuotaLine 对一条限流线发 1-token 复验探针并按结果解除/续窗。
func (s *Scheduler) probeQuotaLine(uid, nickname, model string) {
	a := s.cfg.Pool.AuthByUID(uid)
	if a == nil {
		return
	}
	body := []byte(`{"model":"` + model + `","messages":[{"role":"user","content":"ping"}],"max_tokens":16,"stream":true}`)
	rc, status, respBody, err := s.cfg.Upstream.ChatStream(a, body, "", upstream.ChatMeta{Model: model})
	if err == nil && rc != nil {
		// 成功开流：读首帧即够（复验只要「配额线放行」这个事实，不耗完整回复）。
	buf := make([]byte, 512)
	_, _ = rc.Read(buf)
	rc.Close()
	}
	if err == nil || (status >= 200 && status < 300) {
		s.cfg.Pool.BlockModelClear(uid, model)
		log.Printf("INFO: quota-scan acct=%s model=%s: window reopened, model cooldown cleared",
			logfmt.Label(uid, nickname), model)
		return
	}
	// 429：窗口未开。带新重置时间则按它续窗（截断规则沿用 CooldownSoftForModel）。
	if status == 429 {
		if resetAt, ok := upstream.ParseRateReset(string(respBody)); ok && resetAt.After(time.Now()) {
			s.cfg.Pool.CooldownSoftForModel(uid, quotaScanExtendBase, resetAt, model, "quota scan window extend")
			log.Printf("INFO: quota-scan acct=%s model=%s: still limited, window extended to %s",
				logfmt.Label(uid, nickname), model, resetAt.Format(time.RFC3339))
			return
		}
	}
	log.Printf("quota-scan acct=%s model=%s: probe status=%d (no action)", logfmt.Label(uid, nickname), model, status)
}
