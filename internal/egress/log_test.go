package egress_test

import (
	"bytes"
	"encoding/base64"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/egress"
)

func TestEgressLogsOnlyTypedMetadata(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(407) }))
	defer proxy.Close()
	slot := slotFor(t, proxy.URL)
	slot.Username = "fixture-user"
	slot.Password = "fixture:secret/@"
	m := managerWithSlot(t, slot, egress.Options{AllowedCIDRs: []string{"127.0.0.0/8"}})
	var logs bytes.Buffer
	before := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(before)
	h, err := m.ResolveAccount("account")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Release()
	_, err = send(t, m, h, "http://upstream.invalid/request?state=fixture-oauth-state")
	if err == nil {
		t.Fatal("407 accepted")
	}
	text := logs.String()
	for _, want := range []string{"slot=slot-1", "generation=1", "stage=proxy_response", "code=proxy_auth_failed"} {
		if !strings.Contains(text, want) {
			t.Fatal("missing route diagnostics", text)
		}
	}
	for _, secret := range []string{slot.Username, slot.Password, url.QueryEscape(slot.Password), base64.StdEncoding.EncodeToString([]byte(slot.Username + ":" + slot.Password)), "fixture-oauth-state", "upstream.invalid"} {
		if strings.Contains(text, secret) {
			t.Fatal("secret or request URL in diagnostics")
		}
	}
}
