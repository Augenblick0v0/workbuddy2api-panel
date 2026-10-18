package panel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
)

// cockpitAccount 映射 cockpit tools 导出格式的单个账号。
type cockpitAccount struct {
	ID             string `json:"id"`
	Email          string `json:"email"`
	UID            string `json:"uid"`
	Nickname       string `json:"nickname"`
	AccessToken    string `json:"access_token"`
	RefreshToken   string `json:"refresh_token"`
	TokenType      string `json:"token_type"`
	ExpiresAt      int64  `json:"expires_at"`
	Domain         string `json:"domain"`
	DosageNotify   string `json:"dosage_notify_code"`
	PaymentType    string `json:"payment_type"`
	Status         string `json:"status"`
	UsageUpdatedAt int64  `json:"usage_updated_at"`
	LastCheckin    int64  `json:"last_checkin_time"`
	CheckinStreak  int    `json:"checkin_streak"`
	CreatedAt      int64  `json:"created_at"`
	LastUsed       int64  `json:"last_used"`
	Realm          string `json:"realm"`
	EnterpriseID   string `json:"enterpriseId"`
	DeviceToken    string `json:"device_token"`
}

// decodeImportAccounts accepts cockpit arrays and WorkBuddy account/auth exports.
// Parse every entry before writing credentials; never interpret input as commands.
func decodeImportAccounts(raw []byte) ([]cockpitAccount, error) {
	raw = bytes.TrimSpace(bytes.TrimPrefix(raw, []byte{0xef, 0xbb, 0xbf}))
	if !json.Valid(raw) {
		return nil, fmt.Errorf("invalid JSON document")
	}
	var entries []json.RawMessage
	switch raw[0] {
	case '[':
		if err := json.Unmarshal(raw, &entries); err != nil {
			return nil, err
		}
	case '{':
		entries = []json.RawMessage{raw}
	default:
		return nil, fmt.Errorf("expected an account object or accounts array")
	}
	accounts := make([]cockpitAccount, 0, len(entries))
	for i, entry := range entries {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(entry, &fields); err != nil || fields == nil {
			return nil, fmt.Errorf("account #%d: expected an object", i+1)
		}
		var acc cockpitAccount
		if _, nested := fields["auth"]; nested {
			for _, key := range []string{"account", "auth"} {
				value := bytes.TrimSpace(fields[key])
				if len(value) == 0 || value[0] != '{' {
					return nil, fmt.Errorf("account #%d: expected account and auth objects", i+1)
				}
			}
			a, err := auth.Parse(entry)
			if err != nil {
				return nil, fmt.Errorf("account #%d: invalid WorkBuddy credentials", i+1)
			}
			acc = cockpitAccount{UID: a.UID, Nickname: a.Nickname, AccessToken: a.AccessToken,
				RefreshToken: a.RefreshToken, ExpiresAt: a.ExpiresAt, Domain: a.Domain,
				Realm: a.Realm(), EnterpriseID: a.EnterpriseID, DeviceToken: a.DeviceToken}
		} else {
			if _, ok := fields["access_token"]; !ok {
				return nil, fmt.Errorf("account #%d: expected cockpit credentials or WorkBuddy account/auth export", i+1)
			}
			if err := json.Unmarshal(entry, &acc); err != nil {
				return nil, fmt.Errorf("account #%d: invalid cockpit fields", i+1)
			}
		}
		accounts = append(accounts, acc)
	}
	return accounts, nil
}

// importCockpit 接收 cockpit tools 导出的 JSON 文件，批量导入账号到池中。
//
//	POST /panel/api/import/cockpit
//	Content-Type: multipart/form-data
//	Body: file=<json>
//
// 返回 {ok, total, imported, skipped, errors}。
func (p *Panel) importCockpit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<20)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "parse form: "+err.Error())
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "missing file field: "+err.Error())
		return
	}
	defer file.Close()

	raw, err := io.ReadAll(file)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read file: "+err.Error())
		return
	}

	accounts, err := decodeImportAccounts(raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if len(accounts) == 0 {
		writeErr(w, http.StatusBadRequest, "empty accounts array")
		return
	}

	var total, imported, skipped int
	var errs []string

	for _, acc := range accounts {
		uid := strings.TrimSpace(acc.UID)
		at := strings.TrimSpace(acc.AccessToken)
		rt := strings.TrimSpace(acc.RefreshToken)
		if uid == "" || at == "" || rt == "" {
			skipped++
			errs = append(errs, fmt.Sprintf("missing required fields (id=%s)", acc.ID))
			continue
		}
		if !validImportUID(uid) {
			skipped++
			errs = append(errs, fmt.Sprintf("invalid uid (id=%s)", acc.ID))
			continue
		}

		// 按 domain 推断 realm：workbuddy.ai 家族 → global，否则 cn。
		realm := auth.ResolveRealm(acc.Realm, acc.Domain)

		// cockpit expires_at uses milliseconds; WorkBuddy expiresAt may use seconds.
		expiresAt := acc.ExpiresAt
		if expiresAt >= 100_000_000_000 {
			expiresAt /= 1000
		}
		if expiresAt <= 0 {
			expiresAt = time.Now().Add(365 * 24 * time.Hour).Unix()
		}

		nickname := acc.Nickname
		if strings.TrimSpace(nickname) == "" {
			nickname = acc.Email
		}

		a := &auth.Auth{
			AccessToken:  at,
			RefreshToken: rt,
			ExpiresAt:    expiresAt,
			Domain:       acc.Domain,
			UID:          uid,
			Nickname:     nickname,
			EnterpriseID: acc.EnterpriseID,
			DeviceToken:  acc.DeviceToken,
			FilePath:     filepath.Join(p.cfg.AuthDir, fmt.Sprintf("workbuddy-%s.json", uid)),
		}

		if realm == "global" {
			if _, err := auth.BackfillRealmFor(a, "global"); err != nil {
				skipped++
				errs = append(errs, fmt.Sprintf("uid=%s: set realm failed: %v", uid, err))
				continue
			}
		} else {
			_, _ = a.BackfillRealm()
		}

		// Serialize with OAuth replacement and retain the same pool object, device
		// state, proxy binding and disabled/cooldown state for an existing account.
		uidLock := p.credentialLock(uid)
		uidLock.Lock()
		existing := p.cfg.Pool.AuthByUID(uid)
		if err = os.MkdirAll(p.cfg.AuthDir, 0700); err == nil {
			if existing != nil {
				err = existing.ReplaceCredentials(a)
			} else {
				err = a.SaveAtomic()
			}
		}
		if err == nil && existing == nil {
			p.cfg.Pool.Add(a)
		}
		uidLock.Unlock()
		if err != nil {
			skipped++
			errs = append(errs, fmt.Sprintf("uid=%s: save auth failed: %v", uid, err))
			continue
		}

		if existing != nil {
			imported++
			continue
		}

		// 顺带签到/激活（幂等；失败仅记日志，不阻断导入）。
		if realm == "global" {
			if activated, err := p.cfg.Upstream.GlobalCompleteRegistration(a); err != nil {
				log.Printf("panel: import global 注册激活 uid=%s: %v", uid, err)
			} else if activated {
				log.Printf("panel: import global 注册激活 uid=%s 完成", uid)
			}
			if claimed, err := p.cfg.Upstream.ClaimTrial(a); err != nil {
				log.Printf("panel: import global trial uid=%s: %v", uid, err)
			} else if claimed {
				log.Printf("panel: import global trial uid=%s 已领", uid)
			}
		} else {
			if err := p.cfg.Upstream.DailyCheckin(a); err != nil {
				log.Printf("panel: import checkin uid=%s: %v", uid, err)
			}
		}
		if rm, tt, err := p.cfg.Upstream.UserResource(a); err == nil {
			p.cfg.Pool.ReenableIfCredits(uid, rm, tt)
		}

		imported++
	}

	total = len(accounts)
	log.Printf("panel: cockpit import finished total=%d imported=%d skipped=%d", total, imported, skipped)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"total":    total,
		"imported": imported,
		"skipped":  skipped,
		"errors":   errs,
	})
}

// validImportUID 校验导入 uid 是否可用于拼文件名（同 login.go validUID 口径）。
func validImportUID(uid string) bool {
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
