package server

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestBusyCoordinatorTimingAndGeneration(t *testing.T) {
	g := newBusyCoordinator()
	now := time.Now()
	g.now = func() time.Time { return now }
	g.wait = func(ctx context.Context, d time.Duration, _ <-chan struct{}) error {
		if d <= 0 {
			t.Fatal("unexpected blocking")
		}
		now = now.Add(d)
		return nil
	}
	p := defaultBusyPolicy(5, 3)
	key := "cn\x1fkimi"
	if err := g.note(key, 13*time.Second, p); err != nil {
		t.Fatal(err)
	}
	permit, err := g.acquire(context.Background(), key, p)
	if err != nil {
		t.Fatal(err)
	}
	if !now.Equal(g.keys[key].notBefore) {
		t.Fatal("sent before hint")
	}
	g.note(key, 20*time.Second, p)
	permit.release(true)
	if d := g.remaining(key); d != 20*time.Second {
		t.Fatal("old success erased newer busy", d)
	}
	permit, _ = g.acquire(context.Background(), key, p)
	permit.release(true)
	if g.active(key) {
		t.Fatal("key leaked")
	}
}
func TestBusyCoordinatorFIFOAndCancel(t *testing.T) {
	g := newBusyCoordinator()
	p := defaultBusyPolicy(5, 3)
	g.note("a", time.Nanosecond, p)
	permit, _ := g.acquire(context.Background(), "a", p)
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, e := g.acquire(ctx, "a", p); e != context.Canceled {
			t.Errorf("cancel %v", e)
		}
	}()
	deadline := time.Now().Add(time.Second)
	for {
		g.mu.Lock()
		n := g.waiting
		g.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("waiter not queued")
		}
		time.Sleep(time.Millisecond)
	}
	p.MaxWaitersPerKey = 1
	if _, e := g.acquire(context.Background(), "a", p); e != errBusyCapacity {
		t.Fatal(e)
	}
	if g.active("other-model") {
		t.Fatal("cross-model gate")
	}
	cancel()
	wg.Wait()
	permit.release(true)
	if g.waiting != 0 || len(g.keys) != 0 {
		t.Fatal("leak")
	}
}
func TestBusyCoordinatorConcurrentFIFO(t *testing.T) {
	g := newBusyCoordinator()
	p := defaultBusyPolicy(5, 3)
	g.note("a", time.Nanosecond, p)
	first, _ := g.acquire(context.Background(), "a", p)
	got := make(chan int, 8)
	for i := 0; i < 8; i++ {
		go func(i int) {
			v, e := g.acquire(context.Background(), "a", p)
			if e != nil {
				t.Error(e)
				return
			}
			got <- i
			v.release(true)
		}(i)
		for {
			g.mu.Lock()
			n := g.waiting
			g.mu.Unlock()
			if n == i+1 {
				break
			}
			time.Sleep(time.Millisecond)
		}
	}
	first.release(true)
	for i := 0; i < 8; i++ {
		select {
		case n := <-got:
			if n != i {
				t.Fatalf("FIFO got %d want %d", n, i)
			}
		case <-time.After(time.Second):
			t.Fatal("stuck")
		}
	}
	if g.active("a") {
		t.Fatal("did not drain")
	}
}
