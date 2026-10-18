# 身份矩阵与设备标识迁移（1.14.0-panel-identity.1）

本文件记录 1.14.0 的出站身份升级：**国际版（global）桌面端身份升到 5.8.4**、**国内版（CN）零漂移**、
以及**设备标识语义统一**（桌面端逐账号不变 / 小程序端一次性改为逐账号唯一）。

单一事实来源：`internal/upstream/protocol_profile.go`（`desktopSpec` / `mpSpec` / `protocolFor`）。
除该文件外，非测试 `.go` 代码不得再出现版本号、UA 品牌段、IDE 名、产品名、Origin/Referer/Language
字面量——一律引用矩阵解析结果。

---

## 1. 证据基础

| 编号 | 时间 | 来源 | 关键观测 | 结论 |
|---|---|---|---|---|
| **E1** | 2026-10-16 | Hub mitmproxy 抓包，国际版桌面端 5.8.4，realm=intl / product=workbuddy，对话请求 | `X-IDE-Version: 5.8.4`；`User-Agent: WorkBuddy/5.8.4 workbuddy-ai/5.8.4 CLI/2.161.0`；`X-Agent-Intent: craft`、`X-Agent-Purpose: conversation`、`X-Agent-Type: main`、`X-Private-Data: true`、`X-IDE-Name/Type: WorkBuddy`、`X-Product: SaaS`、`X-Domain: www.workbuddy.ai`，另有 `X-User-Id`/`Authorization`/会话与 trace 族 | 这是 global 桌面端的**目标形态**：版本 5.8.4、UA 次段小写 `workbuddy-ai`、归属头族三件套 + 私标声明 |
| **E2** | 2026-10-18 | 生产机直连上游 `/v3/config` 对比实测（只记录状态码/模型数） | global 账号在 `workbuddy-ai` 与 `WorkBuddy AI` 两个平台段下均 HTTP 200 且 `code == 0`；CN 5.5.4 vs 5.5.6：均 200、60 个模型、`only_old`/`only_new` 均空；global 5.5.4/`WorkBuddy AI` vs 5.8.4/`workbuddy-ai`：均 200、27 个模型、差异为空 | ① 旧注释「global 送错平台段 → 403 `code=11140`」对这两个平台段**不成立**，已改写；② 版本与 UA 平台段升级**不改变模型目录**，故模型探针 UA 可跟随矩阵升级 |
| **E3** | 2026-09（历史实测，本次无新抓包） | CN 桌面端出站实测 | 客户端 `5.5.6`、内置 CLI `2.137.1`、UA 次段 `WorkBuddy`、头组合（`X-Product: WorkBuddy` + `X-Agent-Purpose` + `X-IDE-*` 四头） | CN **零漂移**：唯一允许的变化是内置默认版本数字 5.5.4 → 实测值 5.5.6；**不引入** `X-Agent-Intent` / `X-Agent-Type` / `X-Private-Data` |

> E1 补充：Electron 主进程自己发的旁路请求（msg-center / conversations）UA 是
> `workbuddy-ai/... workbuddy-ai/...`——**不是同一条链路**，不照抄。

---

## 2. 身份矩阵（取值表）

| 维度 | CN 桌面端 | global 桌面端 | CN 小程序端 |
|---|---|---|---|
| 身份名（仅诊断/文档） | `workbuddy-desktop` | `workbuddy-desktop` | `workbuddy-mp` |
| 客户端版本 `client_version` | **5.5.6** | **5.8.4** | 2.4.0 |
| 内置 CLI `cli_version` | 2.137.1 | **2.161.0** | 无（不发送） |
| UA | `WorkBuddy/5.5.6 WorkBuddy/5.5.6 CLI/2.137.1` | `WorkBuddy/5.8.4 workbuddy-ai/5.8.4 CLI/2.161.0` | 不发送 UA（仅 `X-Client-*` 头） |
| UA 品牌段 | `WorkBuddy` | `workbuddy-ai` | — |
| `X-IDE-Name` / `X-IDE-Type` | `WorkBuddy` | `WorkBuddy` | `wx_app_cloud` / `WorkBuddy_MP`（上报体字段） |
| `X-Product` | `WorkBuddy`（`client_name` 默认） | `SaaS` | `SaaS`（上报体） |
| `X-Agent-Purpose` | `conversation` | `conversation` | — |
| `X-Agent-Intent` / `X-Agent-Type` | **不发送** | `craft` / `main` | — |
| `X-Private-Data` | **不发送** | `true` | — |
| Origin / Referer | `https://www.codebuddy.cn` (+`/`) | `https://www.workbuddy.ai` (+`/`) | （billing 域，不设 Origin/Referer） |
| `Accept-Language` | `zh-CN` | `en-US` | — |
| 上报体 `ideVersion`/`extVersion` | 5.5.6 | 5.8.4 | 2.4.0 |

UA 形状规则：`WorkBuddy/<client_version> <品牌段>/<client_version> CLI/<cli_version>`。

### 配置覆盖优先级（显式配置 > 矩阵默认，语义与升级前一致）

| 配置项 | 生效范围 |
|---|---|
| `upstream.client_version` | 桌面端 UA 两处版本段、`X-IDE-Version`、桌面/聊天上报体 `ideVersion`/`extVersion`、billing 单段短 UA（`WorkBuddy/<ver>`）。**不影响**小程序端 2.4.0（升级前即与桌面版本无关，跟随覆盖属规格外新行为） |
| `upstream.cli_version` | 只覆盖 UA 末段 `CLI/<ver>` |
| `upstream.user_agent` | 整段覆盖 UA（品牌段/版本段都不再生效，保留既有兼容语义） |

---

## 3. 各路径头组合对照（升级前 → 升级后）

### CN 桌面端（E3：零漂移）

| 路径 | 升级前 | 升级后 |
|---|---|---|
| chat `/v2/chat/completions` | UA `WorkBuddy/5.5.4 WorkBuddy/5.5.4 CLI/2.137.1`（内置默认）/ `X-IDE-Version: 5.5.4`（默认） | UA `WorkBuddy/5.5.6 WorkBuddy/5.5.6 CLI/2.137.1` / `X-IDE-Version: 5.5.6`（**唯一变化：版本数字对齐实测 5.5.6**） |
| 归属头族 | `X-Product`、`X-Agent-Purpose: conversation`、`X-IDE-Name/Type`、`X-IDE-Version` | 完全一致，且**仍然不发** `X-Agent-Intent`/`X-Agent-Type`/`X-Private-Data` |
| `/v2/report` 桌面上报 | UA 5.5.6 三段式、`X-Product: SaaS`、`X-Domain: <chatBase>`、`X-Request-ID`/`X-User-Id` | 同（`ideVersion`/`extVersion` 取矩阵 5.5.6；**不加** `X-Private-Data`——无抓包证据） |
| billing（签到/余额/活跃上报） | 单段短 UA `WorkBuddy/<ver>`、无 Origin/Referer、无 `X-Machine-ID`/`X-Session-ID` | 同（短 UA 版本跟随矩阵/覆盖） |
| 小程序 `/v2/report` | `X-Client-Product: workbuddy-mp`、`X-Client-Version: 2.4.0`、`machineId` = 全局共享硬编码 | 头集合不变、版本 2.4.0 不变；**`machineId` 改为逐账号唯一**（见 §4） |

### global 桌面端（E1：升级到 5.8.4）

| 路径 | 升级前 | 升级后 |
|---|---|---|
| chat | UA `WorkBuddy/5.5.4 WorkBuddy AI/5.5.4 CLI/2.137.1`、`X-Product: SaaS`、`X-IDE-Version: 5.5.4`、`X-Domain: www.workbuddy.ai`、Origin/Referer `www.workbuddy.ai`、`en-US` | UA `WorkBuddy/5.8.4 workbuddy-ai/5.8.4 CLI/2.161.0`、`X-Product: SaaS`、`X-Agent-Purpose: conversation`、**`X-Agent-Intent: craft`**、**`X-Agent-Type: main`**、**`X-Private-Data: true`**、`X-IDE-Name/Type: WorkBuddy`、`X-IDE-Version: 5.8.4` |
| `/v2/report` 桌面上报 | UA 5.5.6 三段式（CN 常量）、`ideVersion`/`extVersion` 5.5.6 | UA 5.8.4 三段式、`ideVersion`/`extVersion` 5.8.4；头集合不变（**不加** `X-Private-Data`） |
| `/v2/chat/completions` 专家对话 | UA CN 常量、`X-IDE-Version: 5.5.6` | UA/版本取矩阵；global 额外补 `X-Private-Data: true`；`X-Agent-Intent`/`X-Agent-Type` 仍在但取矩阵常量 |
| `/v3/config` 三路模型探针（主路 UA） | CN 桌面 UA 常量 | 按账号 realm 取矩阵 UA（E2：模型目录不变，无需另设 pin） |
| billing | 短 UA + 无设备头 | 同 |

---

## 4. 设备标识迁移策略

### 4.1 桌面端：逐账号不变（存量账号 **0 变化**）

`/v2/report` 的 `machineId`/`sessionId` 由 `desktopMachineID(uid)` / `desktopSessionID(uid)` 派生：

```
machineId = hex(sha256("machine:" + uid))[:36]
sessionId = hex(sha256("session:" + uid))[:36]
```

这与升级前 `deriveID(a, "machine"/"session")` **逐字节相同**（同一盐、同一截断），因此
**已上线的生产账号升级后设备 ID 一个都不变**——不存在「集体换 ID」的批量共性变化。

chat 头的 `X-Machine-ID` / `X-Session-ID` 也切到同一对函数（原 `deriveAccountStableID` 用
`wb2a:` 盐，只影响 chat 头值）。这次统一让「上报体 machineId」与「chat 头 X-Machine-ID」
**同源同值**，不再存在同一账号两套桌面身份的矛盾。

### 4.2 小程序端：一次性改为逐账号唯一

```
mpMachineId = sha256("wb2a:mp:machine:" + uid)  →  16 字节
第 7 字节高 4 位 = 4（version）  第 9 字节高 2 位 = 10（variant）
格式化为 8-4-4-4-12 → 合法 UUIDv4 文本
```

升级前所有账号共用硬编码 `0655736a-607f-4d9d-b430-58176ee9a090`。这是**用户明确要求消除的
批量共性**，故按一次性意图性变化处理：升级后每账号唯一、账号生命周期内稳定。
uid 为空时用固定 `anonymous` 种子，**不得**退化回共享常量。

### 4.3 为什么桌面端不一起改

用户硬边界：已有生产账号不得集体换设备 ID。桌面端现值已是逐账号派生（不是共享常量），
换算法等于给全部存量账号换身份，风险与收益不成比例；小程序端的共享常量才是真正的共性问题。

### 4.4 为什么两类身份不强行统一

桌面身份 = 36 hex（无连字符），小程序身份 = UUIDv4 形态；两者**互不相同、互不派生**。
真实客户端本来就是两套 SDK，强行统一反而是新的无证据突变（协议边界见 §7）。

### 4.5 标识生命周期

| 标识 | 归属 | 生命周期 | 来源 |
|---|---|---|---|
| 桌面 `machineId` / `X-Machine-ID` | 账号 × 桌面身份 | 账号生命周期内永久不变（升级不改值） | 派生自 uid |
| 桌面 `X-Session-ID` | 账号 × 桌面身份 | 永久（真实客户端每次启动会换；网关不伪造轮换，避免无证据突变） | 派生自 uid |
| 小程序 `machineId` | 账号 × 小程序身份 | 账号生命周期内永久（升级后每账号唯一） | 派生自 uid，UUIDv4 形态 |
| `X-Conversation-ID` | 客户端会话 | 透传客户端值；缺失则不发送 | 客户端 |
| `X-Conversation-Request-ID` / `X-Root-Request-ID` | 一次 user send | 该轮所有请求复用同值 | handler 生成 |
| `X-Conversation-Message-ID` / `X-Request-ID` | 单条消息 | 每条消息重新生成（32 hex） | handler 生成 |
| `X-Trace-ID` / `X-B3-*` | 轮次 | 跟随 conversationRequestID / messageID | handler 生成 |

---

## 5. 诊断字段（面板「协议诊断」）

`GET /panel/api/protocol_diagnostics`（需 API Key，离线只读，不发任何上游请求）：

| 字段 | 值 | 含义 |
|---|---|---|
| `international_identity_upgrade` | `applied_global_desktop_5_8_4` | 国际版桌面端已升级到 5.8.4 身份 |
| `device_id_policy` | `per_account_stable_desktop_unified_mp_unique` | 桌面端逐账号稳定（含 chat 头与上报体统一）；小程序端逐账号唯一 |
| `purpose_profiles[]` | 8 行（cn/global × chat/refresh/models/billing），新增 `identity`、`client_version`、`cli_version`、`ide_version`、`agent_intent`、`agent_type`、`private_data` | 每用途实际生效的身份与归属头取值 |
| `identities[]` | 3 行（cn desktop / global desktop / cn mp）：`realm`、`identity`、`user_agent`、`client_version`、`cli_version`、`ide_version`、`origin`、`language`、`product` | 身份矩阵快照；**不含任何设备 ID 或凭据** |
| `accounts[]` | 结构不变 | 账号级设备 Token 来源 / 路由 / 告警 |

面板前端（`internal/panel/app.js`）在用途行追加身份、IDE 版本、X-Agent 三头、私标声明、
机器/会话头有无；并单独渲染 `identities` 行。诊断文本一律 `textContent`，绝不渲染 HTML，
也不显示任何设备 ID。

---

## 6. 风险与回滚

| 风险 | 评估 | 缓解 |
|---|---|---|
| 国际版 WAF 对 5.8.4 UA 或 `workbuddy-ai` 品牌段反应不同 | 低（E2：两个平台段均 200/code=0；模型目录不变） | 出问题按账号/全局回滚配置：`upstream.user_agent` 可整段覆盖 UA |
| 上游后续对 `X-Agent-Intent`/`X-Private-Data` 收紧 | 中（按抓包如实发送） | 仅 global 发送，CN 完全不受影响；异常时先回滚 global 归属头 |
| 小程序端 machineId 换值触发风控 | 低（一次性变化、仍为合法 UUIDv4、逐账号唯一更接近真实客户端） | 保留旧常量于历史文档；如需回退，改 `mpMachineID` 一处即可 |
| 桌面端设备 ID 意外轮换 | 已用测试钉死（固定 uid 字面量期望值 + 独立算式复核） | `/internal/upstream/device_identity_test.go` 回归护栏 |

**回滚方式**：`git revert` 本次提交即可整体回滚；若只想回滚身份取值，改
`internal/upstream/protocol_profile.go` 的矩阵常量（单一事实来源），无需动其他文件。
设备 ID 派生函数在 `internal/upstream/device_identity.go`，同样是单点回滚。

---

## 7. 明确边界（违反即返工）

1. **不把国际配置覆盖到国内账号**：CN 的 UA 品牌段、`X-Product`、`X-IDE-*`、`X-Agent-*` 组合
   与升级前完全一致；CN 唯一允许的变化是内置默认版本 5.5.4 → 实测 5.5.6。
2. **不强行统一所有客户端 ID**：桌面身份（36 hex）与小程序身份（UUIDv4）互不相同、互不派生；
   Web 上报的浏览器指纹也不参与统一。
3. **已有账号不集体换设备 ID**：`/v2/report` 的 `machineId`/`sessionId` 逐账号保持原值；
   只有小程序 `machineId` 从共享硬编码改为逐账号唯一（用户明确要求的一次性变化）。
4. 任务上报载荷**形状不变**，只允许版本/设备标识字段跟随身份矩阵。
