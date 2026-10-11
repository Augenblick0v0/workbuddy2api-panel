package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/egress"
)

// stopEgress never unwraps errors into public messages or retries an uncertain POST.
func stopEgress(w http.ResponseWriter, err error) bool {
	var ee *egress.EgressError
	if !errors.As(err, &ee) {
		return false
	}
	if !strings.HasPrefix(ee.Code, "proxy_") && ee.Code != "oauth_proxy_changed" && !ee.Sent {
		return false
	}
	if ee.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(ee.RetryAfter))
	}
	writeOpenAIError(w, egress.HTTPStatus(ee), ee.Code, "outbound request stopped: "+ee.Code)
	return true
}

type routeWAFGates struct {
	mu      sync.Mutex
	buckets map[string]*wafIPGate
}

func (g *routeWAFGates) note(key, uid string) (time.Time, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.buckets == nil {
		g.buckets = map[string]*wafIPGate{}
	}
	b := g.buckets[key]
	if b == nil {
		b = &wafIPGate{}
		g.buckets[key] = b
	}
	if !b.noteWaf(uid) {
		return time.Time{}, false
	}
	b.mu.Lock()
	until := b.until
	b.mu.Unlock()
	return until, true
}
