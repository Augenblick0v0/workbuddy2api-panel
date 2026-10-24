// credits_summary.go 只读积分汇总接口（GET /panel/api/credits/summary）。
//
// Hub「只读积分汇总接口」的单实例对应物：跨账号聚合当前积分/总额度，按域分组，
// 附可用性与到期压力——面板与外部巡检一跳拿到池子的额度全景，不必逐号拉明细。
// 纯只读：数据全部来自 Pool.List() 的既有快照（余额刷新任务维护），不触发任何
// 上游请求。
package panel

import (
	"net/http"
	"time"
)

type creditsRealmSummary struct {
	Accounts     int   `json:"accounts"`
	Servable     int   `json:"servable"`
	Credits      int64 `json:"credits"`
	CreditsTotal int64 `json:"credits_total,omitempty"`
	Cooling      int   `json:"cooling"`
	Disabled     int   `json:"disabled"`
	Paused       int   `json:"paused"`
}

type creditsSummaryResponse struct {
	Total          creditsRealmSummary            `json:"total"`
	Realms         map[string]creditsRealmSummary `json:"realms"`
	EarliestExpiry string                         `json:"earliest_expiry,omitempty"`
	GeneratedAt    string                         `json:"generated_at"`
}

func (p *Panel) creditsSummary(w http.ResponseWriter, r *http.Request) {
	if p.cfg.Pool == nil {
		proxyError(w, http.StatusServiceUnavailable, "pool_unavailable")
		return
	}
	resp := creditsSummaryResponse{Realms: map[string]creditsRealmSummary{}}
	var earliestUnix int64
	bump := func(realm string, f func(*creditsRealmSummary)) {
		s := resp.Realms[realm]
		f(&s)
		resp.Realms[realm] = s
	}
	for _, st := range p.cfg.Pool.List() {
		var target *creditsRealmSummary
		bump(st.Realm, func(s *creditsRealmSummary) {
			s.Accounts++
			s.Credits += st.Credits
			s.CreditsTotal += st.CreditsTotal
			if st.Disabled {
				s.Disabled++
			} else if st.Paused {
				s.Paused++
			} else if st.Cooling {
				s.Cooling++
			} else {
				s.Servable++
			}
			target = s
		})
		_ = target
		resp.Total.Accounts++
		resp.Total.Credits += st.Credits
		resp.Total.CreditsTotal += st.CreditsTotal
		if st.Disabled {
			resp.Total.Disabled++
		} else if st.Paused {
			resp.Total.Paused++
		} else if st.Cooling {
			resp.Total.Cooling++
		} else {
			resp.Total.Servable++
		}
		if !st.CreditsEarliestExpiry.IsZero() {
			if earliestUnix == 0 || st.CreditsEarliestExpiry.Unix() < earliestUnix {
				earliestUnix = st.CreditsEarliestExpiry.Unix()
			}
		}
	}
	if earliestUnix > 0 {
		resp.EarliestExpiry = unixISO(earliestUnix)
	}
	resp.GeneratedAt = nowISO()
	writeJSON(w, http.StatusOK, resp)
}

func nowISO() string           { return time.Now().UTC().Format(time.RFC3339) }
func unixISO(sec int64) string { return time.Unix(sec, 0).UTC().Format(time.RFC3339) }
