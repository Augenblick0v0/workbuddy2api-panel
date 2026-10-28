package panel

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
)

func TestAccountPriorityAPI(t *testing.T) {
	pl := pool.New("")
	pl.Add(&auth.Auth{UID: "u1"})
	pl.SetCredits("u1", 1234, 0)
	pl.Pause("u1")
	p := New(Config{Pool: pl, APIKey: "key"})
	call := func(uid, body, key string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/panel/api/accounts/"+uid+"/priority", strings.NewReader(body))
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)
		return w
	}
	if w := call("u1", `{"priority":10}`, ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	for _, body := range []string{`{}`, `null`, `{"priority":null}`, `{"priority":-1}`, `{"priority":101}`, `{"priority":1.5}`, `{"priority":"2"}`, `{"priority":10} {}`, `{"priority":10} garbage`, `{"priority":999999999999999999999}`} {
		if w := call("u1", body, "key"); w.Code != 400 {
			t.Errorf("%s: %d", body, w.Code)
		}
	}
	if w := call("unknown", `{"priority":10}`, "key"); w.Code != 404 {
		t.Fatal(w.Code)
	}
	for _, body := range []string{`{"priority":100}`, `{"priority":0}`, `{"priority":10}`} {
		if w := call("u1", body, "key"); w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
	}
	s, _ := pl.Status("u1")
	if s.Priority != 10 || s.Credits != 1234 || !s.Paused {
		t.Fatal(s)
	}
	req := httptest.NewRequest("GET", "/panel/api/overview", nil)
	req.Header.Set("Authorization", "Bearer key")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"priority":10`) {
		t.Fatal(w.Code, w.Body)
	}
}
