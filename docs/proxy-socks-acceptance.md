# 2026-10-11 代理诊断与 SOCKS 增量验收

状态：2026-10-11已部署SOCKS、探针告警及15秒暂态故障恢复修复；两个实际SOCKS槽积分查询成功，其中一个自然超时后无需Probe恢复成功。未绑定HTTP入口的CONNECT400问题独立存在。

## 现场原因

生产基线2a682b3，本地基线77689d0，开发分支feature/proxy-diagnostics-socks。
本轮19:50（Asia/Hong_Kong）重现slot-1检测9ms返回proxy_connect_failed；代际仍1、绑定0。

同机及容器网络命名空间，经39.109.113.97:4090：
- HTTP ipify/ip-api返回200，出口39.109.113.97。
- HTTPS ipify/ip.sb的CONNECT返回400，Server nginx/1.16.1。
- SOCKS5H初始握手返回错误版本；不是可用SOCKS入口。

Sub2API上游固定3a6fd1c9db07203ca308aaba69e502bc1f35b307：
`backend/internal/repository/proxy_probe_service.go:66-67`默认使用HTTP ip-api和HTTP api64.ipify。
Panel旧版仅测HTTPS ipify，并将CONNECT非200合并为proxy_connect_failed。
故障差异是测试目标/通道不同，不是已证实的Panel错误发送CONNECT。
原始容器网络证据：D:\codex\.tmp\panel-proxy-repair-20261011\container-probe.txt。
未读取或修改同机Sub2API生产数据，没有把生产凭据复制到测试。

## 完成范围

- HTTP出口信息与HTTPS独立验证；仍固定目标、有限超时/响应体、禁止重定向。
- CONNECT数字状态、白名单原因/阶段；UI分别展示IP、HTTPS、历史成功与代际状态。
- SOCKS5/5H：远端DNS、匿名/用户名密码认证、255字节限制、拒绝认证降级。
- 请求取消/期限关闭握手连接；成功后移除钩子/期限再复用连接。
- 固定账号/OAuth/维护使用原Manager；继续故障零直连，不引入第三方依赖。
- `verified_ip`将HTTPS证据与HTTP展示IP分离，避免未验证观测污染WAF分组。
- 保持schema1、CAS/代际与原数据结构；CLI和自动发现仍延期。

## 验证记录

1. 失败回归先红后绿：HTTP200+CONNECT400、HTTP失败但HTTPS成功；
   原始SOCKS不支持时四个协议/认证组合均红，支持后通过。
2. 本地 `go test ./internal/egress ./internal/panel ./internal/upstream ./internal/server -count=1` 通过；
   协议取消/代际/WAF修复后重跑egress定向通过。
3. Node语法与22/22行为测试通过（由UI实现agent运行，主agent不重复同状态命令）。
4. Linux Go1.23.12：完整test、vet与egress/panel/upstream/server/pool五包race通过。
   日志：output/playwright/socks-linux-go123-test-final.log、socks-linux-go123-vet-final.log、
   socks-linux-go123-race-final.log。最后新增SOCKS OAuth夹具另做Linux定向race。
5. 四二进制镜像构建完成：workbuddy2api-panel:proxy-socks-candidate，
   image ID `sha256:e03436d1ee3ba9d89f9dc9c01da89c03ae3bd90f258143648d02ace42309ff54`。
   DockerHub frontend授权请求曾超时；本地同Dockerfile仅省略syntax前端拉取指令后构建，
   四条Go构建指令、runtime层和TLS校验均未更改。
6. 实际候选容器E2E（全部合成）：socks5h有认证，聊天、余额、刷新token、重启绑定/token保存通过；
   socks命中11、proxy请求11、direct=0；关代理后502，不罚号。
   结果：output/playwright/candidate-5e6988ee/result.json。
7. 真实Chrome可见窗口：创建/保存/重开SOCKS5H槽、刷新不清表单、
   点击检测实际触发HTTP成功+CONNECT400，页面IP和错误独立显示且无“代际已变”误报。
   桌面1440×900、手机390×844截图已目检，手机正文无新增横向溢出。
   截图：socks-desktop-1440x900.png、socks-editor-desktop.png、
   socks-mobile-diagnostic-390x844.png、socks-mobile-editor-390x844.png，
   均位于output/playwright。浏览器最初未登录产生401和favicon404；
   登录后无新增JS异常。插件连接曾报trusted-service错误，未改全局配置，
   改用已安装Chrome的隔离Playwright会话完成真实界面验证。

## 一次综合审查

集中在网络/取消/认证/持久化风险安排一名独立审查agent，未进行逐任务双审。

- P1：Go Transport取消请求后原生SOCKS握手可能继续等待；改为有界显式握手，
  增加无服务端超时的socket关闭断言。修复后定向复查通过。
- P2：明文HTTP IP原可迁移WAF桶；增加verified_ip并保留旧已验证身份，
  增加“失败探针不得把A保护窗搬到B”回归。修复后定向复查通过。
- 无剩余已知P0/P1。普通上游TLS错误仍可表现为upstream阶段的脱敏错误，
  不强制推断为代理服务器证书故障。

## 流程与剩余范围

- 复用同状态测试证据；审查agent未重复运行测试；UI变化未触发多轮全量构建。
- 首轮Linux运行期间源码有审查修复，首轮结果不作最终基准，已保留失败日志；
  最终代码后集中再跑一次完整测试/vet/race。
- 没有普通源码哈希检查；本轮未向生产传输制品，故没有传输哈希步骤。
- 生产未切换、未重启、未改绑定/凭据。新SOCKS配置回滚旧HTTP-only版本前应检查scheme，
  原版“仅检查空绑定”回滚脚本不直接适用于SOCKS槽；保留最新token/data。
- 实际39.109.113.97:4090对已测HTTPS目标仍拒绝CONNECT；应用更新只改善诊断，
  应由代理方提供支持CONNECT的入口或真实SOCKS服务。真实代理业务验收与生产发布分开记录。

## 同会话续执行核验（2026-10-11 20:08起，Asia/Hong_Kong）

- 用户要求在本会话执行计划；复核后T01–T05已有完整实现及验收，不重复开发。
  T06仍沿用明确批准新版生产切换的边界；本次仅生产只读核对。
- 本地产品源码提交仍为`5172fdadcf81a67e9dd9fbe7a8c526995c6bae67`，
  并确认原Panel固定基线`d66384d9e3d69655f799d7d8f2e5fba1946e00ab`是其祖先。
- 20:08生产HEAD仍为`2a682b3d664fa2dde371eee5b089d6c27563cfc8`，
  运行镜像仍为`workbuddy2api-panel:account-proxy-20261011-136d5ec`，
  容器running/healthy、重启数0。现存`docker-compose.override.yml`保留。
- 当前生产`proxies.json`为schema1、revision8、2个HTTP槽、0个绑定；
  auths内6个文件，config.json存在。只输出数量/协议等非秘密字段，
  未下载生产凭据，未变更检测结果、槽、绑定、配置或服务。
- 当前Docker引擎最初缺少候选镜像，因此补建交付制品。直接构建遇到DockerHub
  frontend授权端点连接超时；仅从stdin省略首行syntax下载指令后成功，
  仓库Dockerfile、Go1.23构建指令和TLS策略未修改。
- 重建镜像ID与上次已验收制品完全一致：
  `sha256:e03436d1ee3ba9d89f9dc9c01da89c03ae3bd90f258143648d02ace42309ff54`。
  记录为`output/playwright/socks-rebuild-20261011.log`（首次失败）及
  `output/playwright/socks-rebuild-native-20261011.log`（成功）。
- 本轮实际执行四程序镜像构建；因源码及镜像均与既有验收一致，复用上述完整
  test/vet/race、22项UI、真实Chrome及candidate-5e6988ee容器E2E证据，
  未重复跑测试、浏览器或另启独立审查。未做额外文件哈希或制品传输。
- 当前结论仍为：**开发完成，生产未发布**。待新版发布明确批准后，
  重新盘点实时生产数据、做一致性备份及恢复校验，再仅切换wb2api；
  真实SOCKS生产验收仍需用户提供有效入口。

## T06正式生产验收（2026-10-11 20:13）

- 用户明确批准部署；生产现运行`workbuddy2api-panel:proxy-socks-20261011-5172fda`，
  镜像ID仍为上文已验收e03436d1，源码c271a8f（产品5172fda）。
- 仅切换wb2api；容器healthy、restarts0，公网healthz200，6账号仍健康。
- 冷备及生产私有目录恢复校验19文件/10JSON与权限属主；账号/token、config、
  2个现有HTTP槽、0绑定保留，旧数据不覆盖当前文件。同机其他服务身份前后不变。
- 现有代理现场检测IP39.109.113.97、HTTPS CONNECT400，stage=connect、
  reason=connect_rejected；只更新观测revision8→9，不改账号路由。
- 发布备份：
  `/opt/workbuddy2api-panel-backups/pre-panel-proxy-socks-20261011-201046`。
- 新回滚入口检查全部槽scheme，包括未绑定的SOCKS槽；先备份最新数据，
  兼容时只回切镜像/源码/override，不恢复历史token/data。
- 本轮一名部署专项审查，修正临时排流规则匹配范围；只做部署相关验证，
  未重复已通过的源码测试、UI验收或E2E。真实SOCKS生产链路仍待入口。
- 完整发布记录：
  `D:\codex\.agentdocs\workflow\261011-panel-proxy-diagnostics-socks-release.md`。

## 后续修复：探针失败仅作诊断（2026-10-11）

用户在将账号绑定HTTP槽后，积分查询报`egress: proxy_unavailable`。
原实现把公共HTTPS探针失败写入整个槽的unavailable运行态，导致真实积分请求尚未发出即失败。

- 在既有Panel管理/积分API接缝加入合成集成回归：
  公共探针CONNECT400，但同一个HTTP代理允许真实积分目标的HTTPS CONNECT。
  修复前测试得到502 `user resource: egress: proxy_unavailable`；
  修复后积分750/1000成功，目标请求1次、直连拨号0次。
- 删除Probe失败对unavailable的写入，底层Transport的探针错误也不污染业务故障状态。
  失败检测仍记录原错误；真实业务代理认证/连接失败、禁用、缺失、WAF和pending保持原阻断。
  已有真实故障不会被失败探针解除，实际失败后不自动重试/切槽/直连。
- UI区分“代理已绑定 · 检测异常”和“代理连接失败”，明确说明检测不会单独阻止账号请求。
  旧代际检测不覆盖当前路由显示；HTTP观测仍不等于HTTPS成功，WAF已验证IP规则不变。
- 定向五包Go测试、23项Node行为测试通过；Linux Go1.23.12全量test/vet与五包race通过。
  新镜像四程序构建成功：`workbuddy2api-panel:proxy-probe-advisory-candidate`，
  ID `sha256:9d30e21e6573f84f7efa04fcc04902d7b8cf9b80dc8ad7d78fce1b21ef06d570`。
- 新镜像分别完成HTTP与SOCKS5H容器E2E：聊天/余额/刷新/重启持久化通过，
  两轮各proxy11、direct0，断代理502且不罚号。一次独立综合审查无阻塞发现，
  并补强失败探针后仍为waf_blocked的断言。
- 真实Chrome使用合成API及当前静态资源，桌面1440×900、手机390×844视口目检通过；
  “检测异常”和说明清晰，无横向溢出。截图为完整页面，不代表生产实际账号数据。
  CLI初始化脚本遇到Windows参数解析和隐藏DOM重复匹配，改为文件输入及可见绑定容器定位后完成。
- 除审查补强测试后的最终Linux验证外，没有重复同状态完整测试；没有源码哈希检查。
  本修复未向生产传输制品、未重启生产、未更改真实账号绑定。
- 另从生产仅做无账号凭据的HTTP/1.1 CONNECT验证：
  slot-1对`www.codebuddy.cn:443`及`www.workbuddy.ai:443`均返回400。
  因此解除探针预阻断不代表当前代理即可完成真实积分查询，入口仍须允许实际业务CONNECT。
- 证据位于`output/playwright/probe-advisory-*`：
  red/green、targeted、ui、linux-test/vet/race、build、http-e2e/socks-e2e日志及两张截图。
- 当前修复结论：**开发完成，生产未发布**。生产仍为已发布的e03436d1镜像，
  后续部署须保留现有新增绑定、账号和最新运行数据，再按批准的发布窗口执行。

### 探针修复正式发布补充（2026-10-11 20:38）
- 用户明确批准后发布a6cdb89，生产镜像9d30e21e；healthy/restarts0、公网healthz200。
- 以最新4槽（含2SOCKS5）、5绑定、6账号文件为准，19文件/10JSON冷备恢复校验通过，
  config/token/代理配置与运行数据保留；其他服务未操作。
- 备份：/opt/workbuddy2api-panel-backups/pre-panel-proxy-advisory-20261011-203641。
- 线上验收时slot-1已有unavailable状态；失败探针CONNECT400前后状态保持，
  一次积分查询仍为502/proxy_unavailable，当前入口积分未成功，不把发布成功等同业务成功。
- 未改变账号绑定/槽代际；仅检测观测revision28→29。回滚目标支持SOCKS，
  守卫拒绝未知协议且保留最新数据；不使用旧版无SOCKS支持的回滚路径。
- 完整记录：D:\codex\.agentdocs\workflow\261011-panel-proxy-probe-advisory-release.md。

## 暂态故障自动恢复修复（2026-10-11）
- 用户发现不检测就积分失败，检测成功后恢复；生产源码证实unavailable为永久bool，
  而成功检测删除它。21:29:51/21:48:21两个SOCKS槽分别失败/超时，随后手测恢复。
- 改为进程内截止时间：真实错误当次停止，默认15秒冷却，到期后仅新请求重试原槽。
  没有后台强制探测、出口轮换、直连回退或失败请求重放；持久schema/API/config未变。
- `Options.FailureCooldown`为Manager进程策略，默认15秒，无管理接口写入口。
  固定账号/OAuth代际、pending、WAF、停用/缺失及账号自身冷却继续独立生效。
- 回归先红：原状态RetryAfter=0；修复后HTTP以及SOCKS5/SOCKS5H均无需Probe恢复。
  持续故障再冷却、默认15秒上限、WAF/停用独立、原槽原代际、直连0均断言通过。
- 本地egress/panel定向测试、24项UI行为通过；LinuxGo1.23.12全量test/vet与五包race通过，
  四二进制镜像构建通过。一次独立集中审查无阻塞发现、未重复运行相同测试。
- 候选`workbuddy2api-panel:proxy-recovery-candidate`，
  ID `sha256:168c44363fb06c1fe78d6bcaae37477c0c92080a432c6330d3bb3bb967f8c78a`。
- UI仅状态标签/说明变更，无布局变化；以新增行为测试确认冷却期限和无需手动解锁，
  复用上一版本真实Chrome桌面/手机布局验收，不重复浏览器流程。
- 日志位于`output/playwright/failure-recovery-*`；正式发布结果另行追加。

### 故障恢复修复正式发布（2026-10-11 22:05）
- 生产6024906、镜像168c4436；健康/restarts0、公网healthz200。
- 提前准备所有制品后快速冷备/切换，准入排流窗口3.795秒，备份恢复19文件/10JSON通过；
  6账号、4槽、5绑定及最新持久数据保留，其他服务未操作。
- 备份：/opt/workbuddy2api-panel-backups/pre-panel-proxy-recovery-20261011-220355。
- 不点Probe直接查询：slot-3积分200；slot-4第一次自然proxy_timeout、RetryAfter15，
  冷却后新一次请求200，全程没有出口检测解锁，slots/bindings/probe_results保持。
- 进程内sticky会话因服务重启重新建立，账号绑定等持久数据保留；未清除账号冷却/WAF保护。
- 正式记录：D:\codex\.agentdocs\workflow\261011-panel-proxy-failure-recovery-release.md。
