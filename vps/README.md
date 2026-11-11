# xnvgatebox VPS Standalone

管理进程、内置 Xray、共享候选池都在 VPS 本地运行，无需额外安装 3x-ui。要求 Linux amd64、root 和 systemd；统一安装入口支持 Debian 12/13、Ubuntu 22.04/24.04 与 CentOS Stream 9/10。各系统自动测试与真实 VPS 验收范围见 [系统兼容性](../docs/LINUX_SUPPORT.md)。

## 安装与升级（v0.9.6）

支持的系统均以 root 执行：

```sh
if command -v apt-get >/dev/null; then apt-get update && apt-get install -y ca-certificates curl; else dnf -y install ca-certificates && { command -v curl >/dev/null || dnf -y install curl; }; fi &&
curl -fsSL https://raw.githubusercontent.com/hanhaoops/xnvgatebox/v0.9.6/vps/install.sh -o /tmp/xnvgatebox-install.sh && bash /tmp/xnvgatebox-install.sh --version v0.9.6 && xnvgatebox access
```

只下载本项目 GitHub Release 的完整包和 SHA256，固定 Xray 在构建时验证官方归档摘要。安装器检查归档路径、类型、重复项、完整文件清单、成员摘要和正式版本构建信息。下载、包校验及本地候选配置检查在停止旧服务之前完成；安装不请求 VPN Gate 来源，保留旧池，没有旧池也可安装。候选由后台或定时器获取。登录后可独立配置本机直出及第三方 SOCKS5，VPN Gate 等待候选，不自动回落直出。

`xnvgatebox access` 查看管理地址和密码，`xnvgatebox version` 查看版本。管理页默认监听 8899，使用随机路径和密码；服务器防火墙需允许管理端口及实际公开接入端口。内部 SOCKS 仅监听本机，外部 SOCKS 需在界面显式启用。

上面的一键安装命令已接上 `xnvgatebox access`，安装成功后直接显示登录信息。首次安装生成独立随机路径、密码和订阅凭据；已有安装更新时继续保留原值。查看命令不会重置密码。重装系统后的全新测试会生成新身份，旧链接需更新或在之后有意恢复备份。

更新入口为“设置 → 版本与更新”或 `xnvgatebox update`；`xnvgatebox check-update` 检查最新正式版，`xnvgatebox update-status` 查看结果。可用 `xnvgatebox update --version v0.9.6` 指定正式版本。旧 v0.4.0 先执行新版安装命令迁移。网页任务独立于管理服务，更新后重新登录查看结果。

备份仅覆盖本项目受管文件，不是整机或 3x-ui 备份；重装前请另存到本机。见 [重装准备](../docs/BACKUP_REINSTALL.md)。

离线包：`bash vps/install.sh --mode vps --package /path/xnvgatebox-linux-amd64.tar.gz`，相邻目录须有 `checksums.txt`。完整包包含管理器、Xray、Python 源码、脚本和服务，不只替换一个二进制。

更新停止本项目服务后备份 `/var/lib/xnvgatebox`、`/usr/local/lib/xnvgatebox`、`/etc/xnvgatebox`、本项目两个命令、环境文件和三个 systemd 单元至 `/var/backups/xnvgatebox/install-<任务编号>/project.tar.gz`，均为私有文件。配置预检后替换完整程序，通过本地登录检查实际运行版本和内置后端。失败恢复原文件及服务启停/开机状态；恢复未完成保留 `/var/lib/xnvgatebox-deploy/transaction.json`，下次安装先恢复。状态与恢复工具独立保存于该目录，不随程序替换丢失。系统依赖包不在回滚范围内，3x-ui 不在受管路径内。

## 首次管理和订阅

1. 执行 `xnvgatebox access`，使用打印的私有地址与密码登录。总览仅保留四步操作提示。
2. 建议在「出口管理」启用「VPS 本机直出」，先使用服务器公网 IP 验证接入；这一步可选，已有就绪的 VPN Gate 出口也可直接使用。
3. 在「我的订阅」复制订阅链接，在 v2rayN 等支持 VLESS / REALITY 的客户端新建订阅分组、粘贴地址并更新；选择直出或已就绪出口，开启客户端代理模式后测试网页。防火墙需允许实际接入端口，只开放管理端口不足以连接代理。
4. 需要 VPN Gate 时，在「出口管理」设置目标数量，国家可留空。程序自动建连、创建并绑定入站，等待「已就绪」后更新原客户端订阅并手动选择。无需预先检测全部候选，也无需手动新增入站。数量和检测并发由使用者设置，真实资源或上游供给不足如实提示等待，不静默降低目标。
5. 有固定代理时，在「代理资源 → 第三方 SOCKS5」填写地址、端口、账号密码及可选国家/城市/备注；保存并检测，确认启用和加入订阅后再更新客户端。
6. 「候选节点」用于按需诊断。「VPS SOCKS5」供其他电脑或程序通过本 VPS 接入，外部端口需显式开启；「原始 SSTP」既可导出给支持 SSTP 的客户端，也可在 VPS 实测通过后选择「加入 VPS 出口池」。后者由 VPS 持续维护 SSTP/PPP 与本机 SOCKS5，可像其他出口一样绑定 VLESS/VMess/Trojan；新增住宅/原生机房分类与 xnvgatebox 稳定池始终分开。普通使用不需另外新增入口；自行新建入口须绑定出口，未绑定会阻断。

候选「检测通过」表示那次临时连通，运行出口「已就绪」才表示当前可加入 VPN Gate 订阅。「地区未知」表示国家证据不足，unknown 不代表家宽；它们与连通状态分开判断。勾选订阅「全选」时单项变灰，取消对应全选后可逐个选择。默认订阅可按来源或指定范围选择，实际仅输出就绪的 VPN Gate 入口。

指定国家使用实测出口 IP 的独立国家证据；ISP/ASN 或住宅类型仍需相应可信画像，不能用来源国家补证。国家查询失败时可保留国家不限且允许 unknown。上游暂时无合适节点时保留策略与端口等待；故障阻断，不自动切换本机直出。客户端须主动更新订阅并选择要用的节点。原始 SSTP 不依赖本 VPS 持续转发，但消费端需自行支持 SSTP，且节点可能失效。

完整步骤及状态表见 [首次使用](../docs/FIRST_USE.md)，其他操作见 [控制台](../docs/CONSOLE.md)、[代理资源](../docs/PROXY_RESOURCES.md) 和 [安装更新及全新验收](../docs/INSTALL_UPDATE.md)。

## 本地刷新

「候选节点 → 周期任务」分别设置候选清单刷新和批量检测，默认 60 分钟，最低 30 分钟，可独立关闭。管理器与 `xnvgatebox-pool.timer` 共用到期记录和构建锁，不重复请求；定时器每 30 分钟检查一次，仅在设定周期到期时获取来源。管理进程每三十秒读取新快照。`xnvgatebox refresh` 或候选页手动刷新不受自动开关和周期限制，触发真实采集，失败保留上一份完整快照。来源配置在 `/etc/xnvgatebox/pool.json`。抓取阶段完整解析官方当次公开响应；数量取决于当次供给，不等于全球所有 VPN Gate，也不等于实测可用数量。

## OpenVPN 出口画像

每次建连时，将 namespace 内两个 HTTPS Echo 得到的基线 IP 交给同一 Python intelligence adapter 和 classifier，再独立检查固定 SOCKS 端口的 actual IP。只有 expected、画像 IP、actual 三者一致才发布该 Slot 的运行证据；画像查询本身不证明隧道或公开订阅可用。

画像服务可选，默认没有配置。查询失败、字段不足或证据过期时，类型显示 `unknown`，不继承 SSTP 画像或来源主机的住宅标签。API 返回部分字段时，缺失布尔值仍为 null；国家、ASN、ISP 和类型以实际 OpenVPN 出口为对象。管理页在 Slot 下展示实际画像，候选表中的国家和延迟明确标为来源信息。

国家另有独立查询：默认按实测出口 IP 请求 `https://api.country.is/{ip}`，正常验证 HTTPS 并精确匹配返回 IP，国家证据有效一天。国家可知不等于住宅类型可知，缺少可信分类画像时仍为 unknown。私有环境文件中的 `COUNTRY_URL_TEMPLATE` 可替换兼容服务（返回 `ip` 与两位 `country`）或设空关闭；失败短暂退避，显示地区未知，不使用来源国家补证。国家查询不发送 `INTELLIGENCE_TOKEN`，也不启用本项目暂停中的 CF 部署。

部署时可在 `/etc/xnvgatebox/intelligence.env` 写入简单的 `KEY=VALUE` 配置，文件只供管理员读取（0600）：

```ini
INTELLIGENCE_URL_TEMPLATE=https://<画像服务主机>/lookup/{ip}
INTELLIGENCE_TOKEN=
```

URL 必须是 HTTPS、包含 `{ip}`，响应格式与现有 adapter 一致，例如包含 `ip`、`country_code`、`asn.asn/name/type` 和 `privacy.is_hosting/is_residential`。可选 token 通过 `X-API-Key` 请求头传递，使用正常 HTTPS 证书验证；配置和 token 不进入订阅或管理页。配置变更在下一次建连时读取，不自动中断当前 Slot，也不需要 Cloudflare 或 Actions 凭据。

缓存位于管理工作目录 `intelligence/cache.json`，由 provider/IP 共同索引，多个 Slot 使用文件锁串行更新；默认有效期为 `pool.json` 的 `intelligence_ttl_seconds`（24 小时）。缓存保留原查询时间，复用时重新执行统一分类规则，不以缓存命中延长有效期。画像进程最多等待 40 秒（含缓存锁等待），超时显示画像不可用。当前版本不会为持续运行的 Slot 自动定时重查画像；到期在 API/UI 中显示 stale/unknown，下一次建连重新查询。

`slot_health.json` 保存本机运行快照：Slot、节点标识、配置 SHA256、固定端口、独立 expected/actual、验证时间及画像证据。文件为 0600，包含原始画像响应，但不含 SOCKS 凭据；管理 API 不返回原始响应。该文件不是历史审计日志，状态保存时会替换；重启恢复不将磁盘画像视为 live/healthy，必须重新验活。

开发环境可单独检查画像入口（该命令不创建或验证隧道）：

```sh
python3 scripts/toolbox.py --config config/settings.json --env-file /path/intelligence.env \
  profile-openvpn --ip <已独立测得的公网IPv4> --cache /path/private-intelligence/cache.json
```

此命令的 JSON 包含原始画像响应，应保存为私有证据。自定义安装路径可通过管理器环境变量 `FANOUT_TOOLBOX_SCRIPT`、`FANOUT_POOL_CONFIG`、`FANOUT_INTELLIGENCE_ENV_FILE` 指定。

“只用家宽”开关现在定义新建 Slot 的默认允许类型：开启时为 strict/likely，关闭时显式允许全部六种类型（包含 unknown）。已经保存的 Slot 策略不随这个全局开关变化。未验证候选可以进入真实探测，但不会因来源名称、SSTP 标签或仅配置画像服务就被认定符合策略。

## Slot 策略与生命周期

新建出口可配置策略，已创建的出口通过“策略”按钮修改。运行中的 Slot 保存新策略后立即阻断业务、关闭旧连接、取消旧探测，再按新策略重新建立 OpenVPN 基线和 SOCKS actual。修改国家或后台节点保留 Slot 编号、SOCKS 端口、namespace 和出站 tag，其他 Slot 不随之重排。

每个 Slot 的策略与恢复配置一起保存于私有 `state.json`：

```json
{
  "country": "US",
  "allowed_ip_types": ["strict_residential", "likely_residential"],
  "preferred_isp": ["Comcast"],
  "allowed_isp": ["Comcast", "Spectrum"],
  "blocked_isp": [],
  "allowed_asn": ["AS7922", "AS20115"],
  "blocked_asn": [],
  "maximum_latency_ms": 1500
}
```

国家留空表示不限；允许类型不能为空，旧 `residential` 值仅兼容为 strict。ISP 和 ASN 的允许/阻止列表为空表示不设该限制，ISP 使用完整名称匹配并忽略大小写，ASN 使用 `AS` 加数字。允许与阻止列表不能包含同一值。preferred ISP 只影响有新鲜实际画像的候选排序，不排除其他 ISP；想限制范围需使用 allowed 列表。

最终国家、类型、ISP、ASN 以本轮真实 OpenVPN 出口画像为准。缺字段不能满足相应硬限制，包含黑名单的策略也不能用缺字段宣称“未命中”；手动指定节点使用相同验活流程。来源国家仅供初筛。未配置画像服务时，不限国家且显式允许 unknown 的技术策略仍可验活；固定国家、ISP/ASN 或住宅类型策略若缺少所需证据会等待，不能用来源信息补齐。

延迟是经固定 SOCKS 端口访问两个 HTTPS Echo 的 curl `time_total`，包含 DNS、连接、TLS 和响应时间，采用两次中较慢者；不是 ICMP ping、来源 ping 或完整公开 Xray 入站延迟。0 表示不限制阈值，正值为毫秒上限；IP 必须仍满足两站 expected/actual 一致。运行期健康监测继续核对画像有效期、出口 IP 和实测延迟，已知不匹配立即阻断并重新验活，不直接执行 expected=actual。

没有候选或没有符合条件的出口时，保留 `waiting_for_nodes`、端口和硬策略，按 5～60 秒退避刷新候选；失败候选冷却 30 秒。并行 Slot 不能占用同一候选或发布相同实际出口 IP。换节点中断原 TCP 连接，不提供无缝切换。

目标国家暂时缺少合适 IP 属于上游可用性条件，不要求程序保证该国随时在线。此时验收程序是否正确提示、保留策略和端口、等待重试并阻断回落；这些行为正常即可通过相应功能检查。该国的正向连通项记录为“上游条件不足，暂未验证”，可在有节点时补测；多出口验收不要求三个不同国家。

内置 Xray 的配置应用仍沿用整体进程重启，绑定恢复或配置更新时，其他 Slot 的已有客户端连接也可能短暂中断；它们的策略、编号和端口保持不变。本轮没有实现 Xray 无缝配置切换。

“停止”只停运行态，保留 Slot、端口、策略、凭据和原绑定；“启动”在同一 Slot 重新验活，重启后已停止的 Slot 也不会自动启动。“删除”才释放 Slot，其他编号不重排；导出保留该编号的显式 blackhole 映射，直至明确重新创建该 Slot。内置 Xray 未绑定或失效的绑定继续阻断。端口被占用时报告失败，不随机换端口。

现有管理登录保护下提供 `GET/POST /api/slot/policy?slot=N`（POST 为上述 JSON）、`POST /api/slot/resume?slot=N` 和 `POST /api/slot/delete?slot=N`。新建的 `/api/provision` 可在原 count/region 参数之外提交同样的 JSON 策略。保存策略失败时保留旧策略并阻断当前 Slot；手动恢复上次策略及失败回退见下节。

旧状态没有 policy 字段时，从原国家代码及已加载的“只用家宽”配置生成默认策略，并重新验活；不会继承旧健康状态或住宅结论。国家画像缺失时会等待合格证据，不能将历史来源国家当作实际出口国家。无效策略、重复 Slot 或端口会拒绝恢复，不启动另一套默认 Slot 来替代。

## 验收与限制

先通过 Slot 的两个 HTTPS expected 探测，再通过 SOCKS 检查 actual 出口并排除母机 IP。客户端全链路仍需实际连接对应公开 Xray 入站确认。类型未知显示 unknown，技术连通不能等同于住宅类型证明。v0.4.0 已发布，并完成真实 VPS 画像国家证据、策略、迁移、订阅和故障恢复验收；具体成功、失败及未覆盖范围见 [Mac 实测](../docs/VPS_UPGRADE_VALIDATION.md#2026-10-15-mac-实测)。

源码中保留原 MIT 许可证和来源记录于 `fanout/UPSTREAM.md`。内部旧目录、兼容环境变量和服务名暂保留，用户入口统一叫 xnvgatebox。


## 配置事务与回滚

以下能力已随 v0.4.0 发布，真实恢复与迁移记录见 [迁移验证](../docs/VPS_UPGRADE_VALIDATION.md)；历史 v0.3.1 的三 Slot 验收不覆盖这些改动。

- 内置 Xray 入站、客户端及绑定变更使用副本生成 `0600` 候选 JSON，先调用 Xray 静态校验，再替换进程和提交配置。校验失败不停止旧进程；后续失败恢复旧文件并用**当前 Slot 状态**重建路由。恢复失败则停止 Xray、拒绝生成可用链接，并保留恢复记录。
- 受管文件通过临时文件、fsync、rename 和私有 undo 记录提交。`.native-transaction.json` 管理 `native.json`、`xray.json`、`native.previous.json`；`.state-transaction.json` 管理 `state.json`；`.management-transaction.json` 管理 `settings.json`、`password`、`basepath`。启动加载相应配置前恢复未完成事务；损坏或不匹配的恢复记录导致报错，不回退到默认配置。这些文件含凭据，不能公开或加入源码。
- 管理设置先验证整份请求；改变监听地址或端口时，先预留新监听，文件全部提交后切换。失败保留旧入口、内存密码/订阅 token，取消候选监听。写入回滚未完成时保留日志、拒绝覆盖，重启继续恢复。
- 内置模式管理页提供“回滚内置配置”，对应受登录保护的 `GET /api/config/rollback`（是否可回滚）及 `POST /api/config/rollback`。只保留上一次成功修改的内置配置，Slot 健康变化不覆盖历史；成功回滚后可切回前一份。恢复会影响入站和客户端凭据，可能让旧链接重新有效，且会重启整个 Xray、中断其他连接。它不回滚 Slot 策略，也不写 3x-ui。
- Slot 策略编辑提供“恢复上次策略”，对应 `POST /api/slot/policy/rollback?slot=N`。每 Slot 保留上一次策略到 `state.json`，重启后仍可恢复。恢复策略和保存新策略走同一路径：先阻断、重新选点并验活；停止状态继续停止。不会恢复旧画像或历史 healthy，无合格节点仍等待。SOCKS 凭据变更失败也会尝试补偿旧运行配置，补偿失败保持阻断。

事务按上述文件组划分，不是跨运行进程、全部文件和外部系统的一次性原子提交；不提供任意历史版本、安装包、CF 或 3x-ui 回滚。进程启动后短暂存活加静态解析只用于发现启动错误，不能替代真实客户端链路验收。普通回归保留合成故障测试；显式启用的 Linux 实测还验证了真实 Xray 拒绝、监听冲突、文件提交/回滚失败及 SIGKILL 恢复，使用一次性副本，不修改安装服务。结果及运行方法见迁移验证文档。

## 升级前离线检查

可执行 `xnvgatebox-fanout -check-state -dir /path/to/private-state-copy`，检查停止服务后取得的内置模式状态副本。该入口不要求 root，不创建目录、修改文件、恢复事务或启动网络服务，输出脱敏 JSON；退出码 0 仅表示持久化结构检查通过。未完成事务、半套凭据及损坏配置会报错，不能靠删除记录或重新生成凭据来掩盖。完整范围、三 Slot 合成样例及真实环境验收记录见 [开发版本迁移验证](../docs/VPS_UPGRADE_VALIDATION.md)。

开发测试包另含 `scripts/vps_acceptance.py`：采集私有计划、从实际订阅验证三个入站、检查本地固定 SOCKS、对唯一确认归属的 Slot OpenVPN 注入故障并观察自动恢复，以及比较升级前后凭据/身份是否保留。外部客户端和 VPS 本机测试分别标记；执行方法及真实验收范围见上述迁移文档。`BUILD.json` 如实记录提交和 dirty 状态；正式发布要求从干净提交构建并与版本标签一致。

## 卸载

`xnvgatebox uninstall --dry-run --purge --legacy` 只读预览；`xnvgatebox uninstall --purge --legacy` 确认后删除本项目、备份及已确认的默认旧版安装。省略 `--purge` 保留已有备份，省略 `--legacy` 保留旧 fanout。旧版本独立工具、清理范围与停止条件见 [卸载说明](../docs/UNINSTALL.md)。
