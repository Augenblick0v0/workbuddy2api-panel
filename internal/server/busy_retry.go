package server

import (
	"context"
	"errors"
	"math/rand/v2"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// BusyRetryPolicy bounds request amplification independently of normal rotation.
// A zero MaxRetries is intentional (disabled); defaults are set by config loading.
type BusyRetryPolicy struct {
	BaseDelay, JitterMax, Budget                     time.Duration
	MaxRetries, MaxChatAttempts                      int
	MaxWaitersPerKey, MaxWaitersTotal, MaxActiveKeys int
}

func defaultBusyPolicy(retries, rotations int) BusyRetryPolicy {
	attempts := retries + 1
	if attempts < rotations {
		attempts = rotations
	}
	return BusyRetryPolicy{5 * time.Second, time.Second, 60 * time.Second, retries, attempts, 8, 32, 64}
}

var errBusyCapacity = errors.New("model busy retry queue is full")

type busyKey struct {
	notBefore  time.Time
	generation uint64
	running    bool
	queue      []*busyWaiter
	changed    chan struct{}
}
type busyWaiter struct{ marker byte }
type busyCoordinator struct {
	mu      sync.Mutex
	keys    map[string]*busyKey
	waiting int
	now     func() time.Time
	wait    func(context.Context, time.Duration, <-chan struct{}) error
}

func newBusyCoordinator() *busyCoordinator {
	return &busyCoordinator{keys: make(map[string]*busyKey), now: time.Now, wait: busyWait}
}
func busyWait(ctx context.Context, d time.Duration, changed <-chan struct{}) error {
	// A nil timer channel means wait for a running predecessor, not busy-spin.
	var timer *time.Timer
	var tick <-chan time.Time
	if d > 0 {
		timer = time.NewTimer(d)
		tick = timer.C
		defer timer.Stop()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-changed:
		return nil
	case <-tick:
		return nil
	}
}
func (g *busyCoordinator) signal(k *busyKey) { close(k.changed); k.changed = make(chan struct{}) }
func (g *busyCoordinator) cleanup() {
	for key, k := range g.keys {
		if !k.running && len(k.queue) == 0 && !g.now().Before(k.notBefore) {
			delete(g.keys, key)
		}
	}
}
func (g *busyCoordinator) note(key string, delay time.Duration, p BusyRetryPolicy) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.cleanup()
	k := g.keys[key]
	if k == nil {
		if len(g.keys) >= p.MaxActiveKeys {
			return errBusyCapacity
		}
		k = &busyKey{changed: make(chan struct{})}
		g.keys[key] = k
	}
	until := g.now().Add(delay)
	if until.After(k.notBefore) {
		k.notBefore = until
	}
	k.generation++
	g.signal(k)
	return nil
}
func (g *busyCoordinator) active(key string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.cleanup()
	return g.keys[key] != nil
}

// acquire is FIFO, cancellable and never holds the mutex across a timer/network.
// A nil permit means the previously busy key has fully drained.
func (g *busyCoordinator) acquire(ctx context.Context, key string, p BusyRetryPolicy) (*busyPermit, error) {
	g.mu.Lock()
	k := g.keys[key]
	if k == nil {
		g.mu.Unlock()
		return nil, nil
	}
	if len(k.queue) >= p.MaxWaitersPerKey || g.waiting >= p.MaxWaitersTotal {
		g.mu.Unlock()
		return nil, errBusyCapacity
	}
	w := &busyWaiter{}
	k.queue = append(k.queue, w)
	g.waiting++
	remove := func() {
		for i, v := range k.queue {
			if v == w {
				k.queue = append(k.queue[:i], k.queue[i+1:]...)
				g.waiting--
				break
			}
		}
		g.signal(k)
	}
	for {
		if err := ctx.Err(); err != nil {
			remove()
			g.mu.Unlock()
			return nil, err
		}
		if !k.running && k.queue[0] == w && !g.now().Before(k.notBefore) {
			remove()
			k.running = true
			permit := &busyPermit{g: g, key: key, k: k, generation: k.generation}
			g.mu.Unlock()
			return permit, nil
		}
		changed := k.changed
		delay := time.Duration(0)
		if !k.running && k.queue[0] == w {
			delay = k.notBefore.Sub(g.now())
		}
		g.mu.Unlock()
		err := g.wait(ctx, delay, changed)
		g.mu.Lock()
		if err != nil {
			remove()
			g.mu.Unlock()
			return nil, err
		}
	}
}
func (g *busyCoordinator) remaining(key string) time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	if k := g.keys[key]; k != nil {
		if d := k.notBefore.Sub(g.now()); d > 0 {
			return d
		}
	}
	return 0
}

type busyPermit struct {
	g          *busyCoordinator
	key        string
	k          *busyKey
	generation uint64
	once       sync.Once
}

func (p *busyPermit) release(accepted bool) {
	if p == nil {
		return
	}
	p.once.Do(func() {
		g := p.g
		g.mu.Lock()
		defer g.mu.Unlock()
		k := p.k
		k.running = false
		if accepted && k.generation == p.generation {
			k.notBefore = g.now()
		}
		g.signal(k)
		if len(k.queue) == 0 && !g.now().Before(k.notBefore) {
			delete(g.keys, p.key)
		}
	})
}
func busyJitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(max) + 1))
}

// busyBudget cancels only the pre-output phase. Accepting the first non-error
// event stops its timer without cancelling the successful streaming context.
type busyBudget struct {
	ctx      context.Context
	cancel   context.CancelFunc
	timer    *time.Timer
	deadline time.Time
}

func newBusyBudget(parent context.Context, d time.Duration) *busyBudget {
	ctx, cancel := context.WithCancel(parent)
	b := &busyBudget{ctx: ctx, cancel: cancel, deadline: time.Now().Add(d)}
	b.timer = time.AfterFunc(d, cancel)
	return b
}
func (b *busyBudget) resume() {
	if b != nil {
		b.timer.Stop()
		if remaining := time.Until(b.deadline); remaining > 0 {
			b.timer = time.AfterFunc(remaining, b.cancel)
		} else {
			b.cancel()
		}
	}
}
func (b *busyBudget) accept() {
	if b != nil {
		b.timer.Stop()
	}
}
func (b *busyBudget) close() {
	if b != nil {
		b.timer.Stop()
		b.cancel()
	}
}

func (h *Handler) busyPolicy() BusyRetryPolicy {
	retries := 5
	if n := h.loadLive().ModelBusyMaxRetries; n != nil {
		retries = *n
	}
	if retries < 0 {
		retries = 0
	}
	if retries > 100 {
		retries = 100
	}
	p := defaultBusyPolicy(retries, h.cfg.MaxRotate)
	if h.busyPolicyOverride != nil {
		p = *h.busyPolicyOverride
	}
	return p
}
func writeModelBusy(w http.ResponseWriter, msg, reason string, d time.Duration) {
	if d < time.Second {
		d = time.Second
	}
	seconds := int64(d / time.Second)
	if d%time.Second != 0 {
		seconds++
	}
	w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
	if msg == "" {
		msg = "model is temporarily busy"
	}
	writeJSON(w, 429, map[string]any{"error": map[string]any{"type": "server_error", "code": "model_busy", "message": msg, "retry_after": seconds, "gateway_hint": reason + "; model congestion does not cool down accounts"}})
}

func (g *busyCoordinator) depth(key string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	if k := g.keys[key]; k != nil {
		return len(k.queue)
	}
	return 0
}
