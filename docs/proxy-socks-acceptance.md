# 2026-10-11 代理诊断与 SOCKS 增量验收

状态：本地候选已实现；生产保持上一版，新增发布需明确批准。真实SOCKS生产地址/账号链未测。

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
