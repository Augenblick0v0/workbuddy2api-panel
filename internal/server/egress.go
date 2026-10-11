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

func (g *routeWAFGates) note(m *egress.Manager, key, uid string) (time.Time, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.buckets == nil {
		g.buckets = map[string]*wafIPGate{}
	}
	for {
		key = m.CanonicalRouteKey(key)
		// Earlier hits may predate the successful probe. Merge them before
		// counting this response so learning an IP cannot reset the threshold.
		for oldKey, source := range g.buckets {
			newKey := m.CanonicalRouteKey(oldKey)
			if oldKey == newKey {
				continue
			}
			dest := g.buckets[newKey]
			if dest == nil {
				g.buckets[newKey] = source
			} else if source != dest {
				mergeWAFGate(dest, source)
			}
			delete(g.buckets, oldKey)
		}
		key = m.CanonicalRouteKey(key)
		b := g.buckets[key]
		if b == nil {
			b = &wafIPGate{}
			g.buckets[key] = b
		}
		blocked := b.noteWaf(uid)
		// A probe published while the buckets were being merged must not
		// strand this last hit in the old unresolved bucket. Recounting the
		// same UID is idempotent; active windows are never extended.
		if next := m.CanonicalRouteKey(key); next != key {
			key = next
			continue
		}
		if !blocked {
			return time.Time{}, false
		}
		b.mu.Lock()
		until := b.until
		b.mu.Unlock()
		return until, true
	}
}

func mergeWAFGate(dest, source *wafIPGate) {
	dest.mu.Lock()
	defer dest.mu.Unlock()
	source.mu.Lock()
	defer source.mu.Unlock()
	if dest.hits == nil {
		dest.hits = map[string]time.Time{}
	}
	for uid, hit := range source.hits {
		if hit.After(dest.hits[uid]) {
			dest.hits[uid] = hit
		}
	}
	if source.until.After(dest.until) {
		dest.until = source.until
	}
}
