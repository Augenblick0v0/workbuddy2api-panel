package upstream

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"regexp"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
)

// fixedUID 测试用固定 uid（期望值已按算法独立算好写在断言里）。
const fixedUID = "u-fixed-uid-001"

// TestDesktopMachineIDNotRotated 设备 ID 不轮换证明（规格 §4/§6）：桌面端
// machineId 必须与升级前逐字节相同——即 `hex(sha256("machine:"+uid))[:36]`。
// 该算法是升级前 desktop.go deriveID(a,"machine") 的实现，此处用独立算式复核，
// 确保「升级不改存量账号设备 ID」这条硬边界（0 变更）有回归护栏。
func TestDesktopMachineIDNotRotated(t *testing.T) {
	sum := sha256.Sum256([]byte("machine:" + fixedUID))
	if want, got := hex.EncodeToString(sum[:18]), desktopMachineID(fixedUID); got != want {
		t.Fatalf("desktopMachineID rotated: got %q want %q (must be identical to pre-upgrade value)", got, want)
	}
	// 固定期望值（同一算式的字面量快照，双保险：算法被改也能立刻发现）。
	if got, want := desktopMachineID(fixedUID), "a5e9cda135ff2d691ff040e6c85cd5e727bf"; got != want {
		t.Fatalf("desktopMachineID = %q want %q", got, want)
	}
	sum = sha256.Sum256([]byte("session:" + fixedUID))
	if want, got := hex.EncodeToString(sum[:18]), desktopSessionID(fixedUID); got != want {
		t.Fatalf("desktopSessionID rotated: got %q want %q", got, want)
	}
	if got, want := desktopSessionID(fixedUID), "7de0bd826769f3440826208804550842b644"; got != want {
		t.Fatalf("desktopSessionID = %q want %q", got, want)
	}
}

// TestChatHeadersUseDesktopDeviceIdentity chat 头的 X-Machine-ID / X-Session-ID
// 与上报体 machineId / sessionId 同源（规格 §4「统一到设备母身份」）。
func TestChatHeadersUseDesktopDeviceIdentity(t *testing.T) {
	a := &auth.Auth{AccessToken: "at", UID: fixedUID, Domain: "copilot.tencent.com"}
	a.BackfillRealm()
	h := chatHeaderSet(t, New(), a)
	if got, want := h.Get("X-Machine-ID"), desktopMachineID(fixedUID); got != want {
		t.Errorf("X-Machine-ID = %q want %q", got, want)
	}
	if got, want := h.Get("X-Session-ID"), desktopSessionID(fixedUID); got != want {
		t.Errorf("X-Session-ID = %q want %q", got, want)
	}
	// 与上报体同源：desktopFingerprint 的两个字段取同一函数。
	c := New()
	fp := c.desktopFingerprint(a)
	if fp["machineId"] != desktopMachineID(fixedUID) || fp["sessionId"] != desktopSessionID(fixedUID) {
		t.Errorf("report fingerprint device IDs diverged: %v", fp)
	}
}

// TestMPMachineIDPerAccountUnique 小程序端 machineId（规格 §4/§6）：升级后逐账号
// 唯一、调用稳定、UUIDv4 文本形态，且不再等于旧的共享硬编码常量。
func TestMPMachineIDPerAccountUnique(t *testing.T) {
	const oldShared = "0655736a-607f-4d9d-b430-58176ee9a090"
	uuidV4 := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

	first, second := mpMachineID(fixedUID), mpMachineID("u-fixed-uid-002")
	if first == second {
		t.Fatalf("mp machineId must differ per account, both = %q", first)
	}
	if first != mpMachineID(fixedUID) {
		t.Fatalf("mp machineId not stable across calls")
	}
	if first == oldShared || second == oldShared {
		t.Fatalf("mp machineId still equals retired shared constant %q", oldShared)
	}
	if !uuidV4.MatchString(first) || !uuidV4.MatchString(second) {
		t.Fatalf("mp machineId not UUIDv4 form: %q / %q", first, second)
	}
	// 空 uid 不退化回共享常量：用固定 anonymous 种子保持「逐账号唯一」的意图。
	if got := mpMachineID(""); got == oldShared || !uuidV4.MatchString(got) {
		t.Fatalf("empty-uid mp machineId = %q", got)
	}
	if mpMachineID("") != mpMachineID("") {
		t.Fatalf("empty-uid mp machineId not stable")
	}
	// mpEventBase 实际使用同一个派生值。
	a := &auth.Auth{UID: fixedUID}
	base := (&Client{}).mpEventBase(a)
	if base["machineId"] != first {
		t.Fatalf("mpEventBase machineId = %v want %q", base["machineId"], first)
	}
}

// TestDesktopAndMPDeviceIDsDistinct 两类身份的设备 ID 形态不同、取值不等，且互不
// 派生（规格 §1 边界 3：不得把桌面端/小程序端 ID 强行统一）。
func TestDesktopAndMPDeviceIDsDistinct(t *testing.T) {
	desktop := desktopMachineID(fixedUID)
	mp := mpMachineID(fixedUID)
	if desktop == mp {
		t.Fatalf("desktop and mp device IDs must not be equal (%q)", desktop)
	}
	if len(desktop) != 36 {
		t.Fatalf("desktop machineId len = %d want 36 hex", len(desktop))
	}
	if _, err := hex.DecodeString(desktop); err != nil {
		t.Fatalf("desktop machineId must be hex: %v", err)
	}
	// 形态不同：桌面端 36 位无连字符；小程序端 UUIDv4 带连字符。
	if regexp.MustCompile(`-`).MatchString(desktop) {
		t.Fatalf("desktop machineId must not be UUID form: %q", desktop)
	}
	if desktop == desktopSessionID(fixedUID) {
		t.Fatalf("machineId and sessionId must differ")
	}
	// 空 uid 不注入设备头（保持升级前行为）。
	r, _ := http.NewRequest("GET", "https://fixture.invalid/x", nil)
	c := New()
	c.injectAccountStableHeaders(r, &auth.Auth{})
	if r.Header.Get("X-Machine-ID") != "" || r.Header.Get("X-Session-ID") != "" {
		t.Fatalf("empty uid must not inject device headers")
	}
}
