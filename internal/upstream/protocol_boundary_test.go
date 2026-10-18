package upstream

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
)

func TestProtocolTaskHeadersUnchangedWhenAPIHardeningEnabled(t *testing.T) {
	for _, domain := range []string{"", "www.workbuddy.ai"} {
		for _, custom := range []bool{false, true} {
			a := &auth.Auth{UID: "fixture", Domain: domain, AccessToken: "synthetic-access"}
			c := &Client{DeviceToken: "synthetic-shared"}
			if custom {
				c.UserAgent, c.ClientVersion, c.CliVersion, c.ClientName = "fixture-ua", "fixture-ver", "fixture-cli", "fixture-name"
			}
			capture := func(enabled bool) http.Header {
				c.AccountDeviceTokenOnly.Store(enabled)
				r, _ := http.NewRequest("POST", "https://fixture.invalid/v2/report", nil)
				c.BillingHeaders(r, a)
				return r.Header
			}
			original, hardened := capture(false), capture(true)
			if !reflect.DeepEqual(original, hardened) {
				t.Fatal("API token policy changed task/billing headers", original, hardened)
			}
			if hardened.Get("X-Device-Token") != "synthetic-shared" {
				t.Fatal("task device fallback must remain unchanged")
			}
			// Task chat callers use zero-value APIRequest and keep legacy behavior.
			r, _ := http.NewRequest("POST", "https://fixture.invalid/v2/chat/completions", nil)
			c.ChatHeaders(r, a, "", ChatMeta{})
			if r.Header.Get("X-Device-Token") != "synthetic-shared" {
				t.Fatal("task chat token behavior changed")
			}
		}
	}
}

func TestProtocolAPIAccountTokenDoesNotBorrowSharedCredential(t *testing.T) {
	c := &Client{DeviceToken: "synthetic-shared", DeviceTokenFile: "/not/read/by/api"}
	c.AccountDeviceTokenOnly.Store(true)
	a := &auth.Auth{UID: "u", AccessToken: "synthetic-access"}
	request := func() *http.Request {
		r, _ := http.NewRequest("POST", "https://fixture.invalid/v2/chat/completions", nil)
		c.ChatHeaders(r, a, "", ChatMeta{APIRequest: true})
		return r
	}
	if request().Header.Get("X-Device-Token") != "" {
		t.Fatal("API borrowed shared credential")
	}
	if c.APIDeviceTokenDiagnostic(a).Source != "none" {
		t.Fatal("diagnostic must reflect suppression")
	}
	a.DeviceToken = "synthetic-owned"
	if request().Header.Get("X-Device-Token") != a.DeviceToken {
		t.Fatal("owned credential lost")
	}
	a.DeviceToken = ""
	c.AccountDeviceTokenOnly.Store(false)
	if request().Header.Get("X-Device-Token") != c.DeviceToken {
		t.Fatal("explicit legacy compatibility policy lost")
	}
}

func TestProtocolPurposeMatrixAndSafeEndpointPreview(t *testing.T) {
	c := New()
	c.ChatBaseGlobal = "https://synthetic-user:synthetic-password@global.fixture/path?token=synthetic-secret"
	rows := c.ProtocolPurposeProfiles()
	if len(rows) != 8 {
		t.Fatal("missing realm/purpose combinations")
	}
	for _, p := range rows {
		if p.Realm == "global" && p.Purpose != "billing" && p.EndpointOrigin != "https://global.fixture" {
			t.Fatal("endpoint preview disclosed path, query or credentials", p.EndpointOrigin)
		}
		if p.Purpose == "billing" && (p.Origin != "" || p.MachineHeader || p.SessionHeader) {
			t.Fatal("billing diagnostic invented headers")
		}
		if p.Realm == "cn" && p.Purpose == "chat" && p.UserAgent != "WorkBuddy/5.5.4 WorkBuddy/5.5.4 CLI/2.137.1" {
			t.Fatal("CN identity changed")
		}
	}
}

func TestProtocolExistingDeviceAndRequestLifecyclePreserved(t *testing.T) {
	c := &Client{}
	a := &auth.Auth{UID: "fixture", AccessToken: "synthetic"}
	meta := ChatMeta{ConversationID: "synthetic-conversation", ConversationRequestID: "00112233445566778899aabbccddeeff"}
	var headers []http.Header
	for i := 0; i < 2; i++ {
		r, _ := http.NewRequest("POST", "https://fixture.invalid", nil)
		c.ChatHeaders(r, a, "", meta)
		headers = append(headers, r.Header)
	}
	for _, key := range []string{"X-Machine-ID", "X-Session-ID", "X-Conversation-ID", "X-Conversation-Request-ID", "X-Root-Request-ID"} {
		if headers[0].Get(key) != headers[1].Get(key) {
			t.Fatal("existing stable lifecycle changed", key)
		}
	}
	if headers[0].Get("X-Request-ID") == headers[1].Get("X-Request-ID") {
		t.Fatal("message IDs must remain unique")
	}
}
