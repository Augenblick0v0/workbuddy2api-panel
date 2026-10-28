package panel

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
)

// accountPriority 沿用面板 Bearer 鉴权和池状态持久化；缺字段不隐式重置为 0。
func (p *Panel) accountPriority(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Priority *int `json:"priority"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	if err := dec.Decode(&body); err != nil || body.Priority == nil || *body.Priority < 0 || *body.Priority > pool.MaxPriority {
		writeErr(w, http.StatusBadRequest, "priority must be an integer between 0 and 100")
		return
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	uid := r.PathValue("uid")
	if !p.cfg.Pool.SetPriority(uid, *body.Priority) {
		writeErr(w, http.StatusNotFound, "account not found")
		return
	}
	log.Printf("panel: priority uid=%s priority=%d", uid, *body.Priority)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "priority": *body.Priority})
}
