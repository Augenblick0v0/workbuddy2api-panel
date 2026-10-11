# 账号固定出站代理

开发候选基于 Panel `d66384d9e3d69655f799d7d8f2e5fba1946e00ab`，不包含版本升级。
开发验收证据见 `proxy-acceptance.md`。生产发布单独审批；当前未发布。

## 使用边界

- HTTP/HTTPS 代理槽、账号固定绑定；没有自动轮换、代理发现或 SOCKS。
- 只覆盖常驻 Panel 的聊天、刷新、目录、维护和服务端 OAuth 请求。
  `cmd/login`、`cmd/signin`、`cmd/credit` 及独立 Python/shell 脚本保持延期。
  **绑定账号之后只通过常驻服务维护，旧 CLI/脚本不会继承绑定。**
- 未分配与显式直连是两种管理状态；两者均直连，但批量分配只处理未分配。
  已绑定、显式直连、disabled/paused 账号不会被批量分配改动。
- 槽 ID 不回收。禁用槽保留绑定，删除账号保留孤立绑定。重新导入 UID 沿用绑定。
- 槽不同不代表公网 IP 不同；已知同 IP 的槽共享 WAF 保护窗。
  检测成功不是账号可用或账户限制已解除的证据。

## 配置与秘密保护

`proxies.json` 位于 `state_file` 的同目录，与旧 state/Redis schema 分开。
生产预期路径为 `/opt/workbuddy2api-panel/data/proxies.json`（容器 `/app/data/proxies.json`）。
它含代理用户名/密码，应为0600，目录归运行用户10001所有；使用整个 data 目录挂载，
不要单文件挂载代理文件，否则会破坏同目录原子替换。

管理界面只返回 `has_password`。密码输入仅写入，留空编辑保留原密码，
`clear_password:true` 显式清除；不放进浏览器 localStorage，不回填进 HTML。
新管理接口要求非空 API key；通过 HTTPS/受控管理网络使用。
分享业务 API key 的部署在发布前必须另行隔离管理入口。
浏览器写入校验 Origin，脚本可使用无 Origin 的 Bearer 请求。

默认禁止私网代理地址。确需局域网代理时，在启动配置中显式允许网段，例如：

```json
{"egress":{"allowed_proxy_cidrs":["192.168.50.0/24"]}}
```

该配置需重启；metadata/link-local/多播地址始终拦截，DNS在实际拨号时复核。
Docker的127.0.0.1指容器本身，宿主代理需要配置容器可达地址。
显式 direct 不读取 HTTP_PROXY/HTTPS_PROXY 环境变量；原本依赖环境代理的部署
应迁移为明确的槽/绑定配置后再采用候选。

## 操作顺序

1. 添加槽，手动出口测试（固定 `https://api.ipify.org?format=json`，10秒，16KiB，
   不跳转、不带账号凭据；界面不接任意测试URL）。
2. 单账号选择槽，或预览批量分配后确认。任何 revision 冲突先刷新/重预览，
   不在后台强行覆盖他人的编辑。
3. 修改配置只影响后续请求；已有 SSE 流可正常完成。禁用/缺失/不可用/WAF窗
   阻断后续出站，故障不直连、不借用其他代理。
4. 修好网络后手动测试可恢复网络可用性；测试不会清除 WAF 窗口。
   失败检测保留上次成功 IP/成功时间并标记陈旧，最近尝试时间单独显示。
5. 删除槽前显式处理绑定并取消使用它的 OAuth 会话。
   孤立绑定需操作者确认清理，服务不会自动清理。

## OAuth

发起前选择服务端代理；state/token/account及首次注册/余额使用固定槽/代际。
浏览器打开的官方授权网页仍使用**浏览器自己的网络**，不自动改系统或浏览器代理。
中途改槽、禁用或网络终态失败停止会话，重新发起；同state轮询单飞，完成结果缓存。
新UID先持久化绑定，再写凭证，再入池，避免崩溃重启后当成未分配直连。
已有UID选择不同出口需明确 `confirm_rebind=true`；未确认保留旧凭证/绑定。
凭证写失败保留孤立绑定，便于人工恢复。重新登录保留原账号对象/文件路径及
设备标识；运行时 credential epoch 阻止旧刷新响应覆盖新token，不改变凭证JSON schema。
绑定提交同时写入持久 `pending_accounts` 保护：已有UID也在凭据提交窗口停止选号和维护。
凭据写入或最终路由提交失败时保护跨重启保留；修复写入条件后，重新发起同一出口的
OAuth完成凭据提交即可解除，手动改绑或出口检测不会偷偷解除保护。

## 管理 API

均在 `/panel/api`，Bearer鉴权：

| 操作 | 方法/路径 | 主要字段 |
|---|---|---|
| 列表 | GET `proxies` | revision、脱敏slots、accounts路由/孤立状态 |
| 创建 | POST `proxies` | revision、name、scheme、host、port、username、password、operation_id |
| 编辑 | PATCH `proxies/{id}` | revision、变更字段、clear_password |
| 删除 | DELETE `proxies/{id}` | revision；绑定或OAuth在用409 |
| 绑定 | PUT `accounts/{uid}/proxy` | revision、slot_id；空字符串显式直连 |
| 孤立清理 | DELETE `accounts/{uid}/proxy` | revision、confirm:true；账号仍在池中409 |
| 批量预览 | POST `proxies/assign` | preview:true、expected_revision、realm、uids |
| 批量确认 | POST `proxies/assign` | expected_revision、assignments、operation_id |
| 出口检测 | POST `proxies/{id}/test` | `{}` 或 generation |
| OAuth发起 | POST `login/start` | realm、proxy_slot_id、confirm_rebind |
| OAuth轮询 | GET `login/poll` | state；显式确认时confirm_rebind=true |
| OAuth取消 | POST `login/cancel` | state |

创建/批量确认的 operation_id 重试结果跨重启保留；同ID异请求409。
代理错误使用稳定code，不把407/代理TLS故障算作账号失效。
已发送或结果未知的POST不自动重放；普通确定上游5xx的聊天策略保持旧语义。

## 文件一致性与恢复

存储CAS串行、临时文件fsync、同目录rename，成功后发布不可变快照。
已有文件损坏/权限异常停止启动，运行中提交前写失败保留旧配置。
rename是提交点；提交后的目录fsync为best-effort，其失败不制造磁盘/内存revision
分裂，但断电持久性依赖文件系统。候选按单常驻进程写入，禁止多个进程共享写文件。

发布前停止目标流量并等待在途请求，停止该Panel的scheduler写入后做一致性备份：
auths、data、config.json、Compose、旧镜像引用与权限属主。先在隔离目录验证恢复。
不操作同机NewAPI/Sub2API/9Router，不把生产凭据复制到测试环境。

**旧1.13.0忽略代理绑定，回滚后禁止直接接流量。** 优先回滚支持代理的候选；
若只能回原版，保持Panel停止/入口隔离，待明确选择direct或停止相关账号业务和维护。
回滚优先只换制品；保留发布后最新token、冷却、用量、任务、日志、proxies.json，
不要整份旧auths/data覆盖回来。
