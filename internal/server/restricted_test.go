package server

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestRestrictedGateWave(t *testing.T) {
	oldWindow, oldHold := restrictedWindow, restrictedHold
	restrictedWindow, restrictedHold = 200*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { restrictedWindow, restrictedHold = oldWindow, oldHold })

	var g restrictedGate
	var pauses atomic.Int64
	pause := func() { pauses.Add(1) }

	// 同一账号反复命中：只计 1 个号，永不触发整池暂停。
	for i := 0; i < 5; i++ {
		if g.noteRestricted("u1", "global", pause) {
			t.Fatal("single account must never trigger the wave")
		}
	}
	if pauses.Load() != 0 {
		t.Fatal("no pause expected before threshold")
	}
	// 第二个不同账号在窗内命中 → 波形激活，执行整池暂停。
	if !g.noteRestricted("u2", "global", pause) {
		t.Fatal("two distinct accounts within the window must activate")
	}
	if pauses.Load() != 1 {
		t.Fatalf("pause callback runs once, got %d", pauses.Load())
	}
	// 激活后窗口清空：紧接的第三号不重复触发。
	if g.noteRestricted("u3", "global", pause) {
		t.Fatal("wave must not re-arm immediately after activation")
	}
	if pauses.Load() != 1 {
		t.Fatalf("pause still once, got %d", pauses.Load())
	}
	// 窗口过期后重新计波形。
	time.Sleep(250 * time.Millisecond)
	if g.noteRestricted("u4", "global", pause) {
		t.Fatal("stale hits must expire (u4 alone is one account)")
	}
	if !g.noteRestricted("u5", "global", pause) {
		t.Fatal("fresh pair must activate again")
	}
	if pauses.Load() != 2 {
		t.Fatalf("second wave pause expected, got %d", pauses.Load())
	}
}
