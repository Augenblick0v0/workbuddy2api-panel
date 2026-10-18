package upstream

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
)

// ─────────────────────────────────────────────────────────────────────────────
// 设备标识派生（规格 §4）
//
// 三条硬边界（规格 §1）：
//  1. 桌面端身份（36 hex）与小程序端身份（UUIDv4 形态）**互不相等、互不派生**，
//     不能为了「统一」把两端 ID 强行改成同一个值；
//  2. 既有生产账号的桌面端 machineId / sessionId 取值**必须保持逐账号不变**——
//     升级只换版本与 UA，不许批量换设备 ID（否则上游侧等同新设备，风控语义全变）；
//  3. 小程序端 machineId 是唯一一次「有意的」变更：旧值是一个全仓共享硬编码常量
//     （0655736a-607f-4d9d-b430-58176ee9a090），多账号共用同一设备指纹本身即风险，
//     改为逐账号唯一（用户明确要求）。
//
// 实现上不引入任何持久化存储：值完全由 uid 确定性派生（sha256），
// 因此跨进程重启恒定、跨账号互异、无状态可丢；空 uid 一律不注入（保持既有行为）。
// ─────────────────────────────────────────────────────────────────────────────
const (
	// deviceIDBytes 桌面端 ID 取 sha256 前 18 字节 → 36 hex 字符（与升级前取值一致）。
	deviceIDBytes = 18
	// mpMachineSalt 小程序端 machineId 的派生盐（与桌面端盐空间隔离，杜绝两端碰撞/同源）。
	mpMachineSalt = "wb2a:mp:machine:"
	// anonymousSeed 空 uid 的固定种子：保证派生结果仍是「确定的唯一值」，
	// 不会退化成多个匿名账号共享同一个广播常量。
	anonymousSeed = "anonymous"
)

// deriveHexID 由「盐 + uid」确定性派生 n 字节 hex 字符串。
// 与仓库既有派生（session/ids.go、cache_key.go）同为 sha256，跨重启稳定。
func deriveHexID(salt, uid string, n int) string {
	sum := sha256.Sum256([]byte(salt + ":" + uid))
	if n > len(sum) {
		n = len(sum)
	}
	return hex.EncodeToString(sum[:n])
}

// desktopMachineID 桌面端设备标识 / X-Machine-ID：36 hex。
// 取值与升级前 `/v2/report` 的 machineId 完全一致（旧实现为 sha256("machine:"+uid)
// 前 18 字节 hex），因此对既有账号是**零变更**，只把算法收敛到本文件统一实现。
func desktopMachineID(uid string) string {
	return deriveHexID("machine", uid, deviceIDBytes)
}

// desktopSessionID 桌面端会话标识 / X-Session-ID：36 hex。
// 同样与升级前取值一致（sha256("session:"+uid) 前 18 字节 hex）。
// 真实客户端每次启动会换 sessionId，但网关侧无持久化可存「本次启动」状态——
// 伪造轮换属于无证据的变更，故保持账号级恒定（规格 §4 生命周期表）。
func desktopSessionID(uid string) string {
	return deriveHexID("session", uid, deviceIDBytes)
}

// mpMachineID 小程序端 machineId：UUIDv4 文本形态（8-4-4-4-12），逐账号唯一。
// 取代旧的共享硬编码常量；版本位固定 4、变体位固定 10xx，形状与真实 UUIDv4 一致，
// 但**不是**从桌面端 ID 截断/拼接而来（不同盐空间，规格 §1 第 3 条）。
func mpMachineID(uid string) string {
	seed := uid
	if seed == "" {
		seed = anonymousSeed
	}
	sum := sha256.Sum256([]byte(mpMachineSalt + seed))
	var b [16]byte
	copy(b[:], sum[:16])
	b[6] = (b[6] & 0x0f) | 0x40 // version = 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant = RFC4122 (10xx)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// deriveID 按 uid + 用途盐派生 36 hex 标识（桌面端其它用途：req / webmachine /
// qimei36 等沿用同一派生空间，取值与升级前一致）。a 为空时按空 uid 派生。
func deriveID(a *auth.Auth, salt string) string {
	uid := ""
	if a != nil {
		uid = a.UID
	}
	return deriveHexID(salt, uid, deviceIDBytes)
}
