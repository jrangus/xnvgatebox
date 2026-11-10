# xnvgatebox

在自己的 VPS 上管理 VPN Gate、第三方 SOCKS5 和本机直出，通过一个订阅链接在 v2rayN 等客户端使用。

- **多种出口**：自动连接 VPN Gate，也可手动添加固定 SOCKS5 地址、账号和密码。
- **网页管理**：管理出口、接入、检测并发、周期任务、国家策略与订阅范围。
- **统一订阅**：支持 v2rayN 与 Clash/Mihomo 格式，按本机直出、自定义代理、VPN Gate 排序，显示国家和自定义备注。
- **独立运行**：内置 Xray，无需额外安装 3x-ui，也不需要 Cloudflare 或 GitHub 账号。
- **更新与恢复**：支持网页更新、更新前备份、失败恢复及完整卸载。
- **原始 SSTP**：检测并导出 VPN Gate SSTP 资源，供支持 SSTP 的客户端直接使用。

## 安装

需要 root、Linux x86_64、systemd 和可用的 TUN/network namespace。支持范围与各系统测试结果见 [系统兼容性](docs/LINUX_SUPPORT.md)。

当前版本：[v0.9.6](https://github.com/hanhaoops/xnvgatebox/releases/tag/v0.9.6)。统一安装入口支持 Debian 12/13、Ubuntu 22.04/24.04 和 CentOS Stream 9/10。六个系统已通过自动安装、更新及卸载测试；CentOS 独立 VPS 验收尚未完成。CentOS 7/8（含 Stream 8）不在支持范围。

## 3x-ui 补充出口池

`jrangus` 分支为 3x-ui 集成增加了一个与原稳定隧道完全隔离的可选池：

- 原有 VPN Gate + xnvgatebox 槽位始终标记为 `xnvgatebox_stable`；
- 免费公开 SOCKS5 只作为候选，必须由 VPS 重做双出口 IP、HTTPS 内容、远程 DNS、地区和 IP 类型检测；
- 只有 `strict_residential` / `likely_residential` 进入 `new_residential`；
- 只有原生地区证据通过且属于 `datacenter` / `business_isp` 的出口进入 `new_native_datacenter`；
- 新增池使用 `100000-999999` 独立确定性槽位，不占用或替换稳定池槽位；
- 刷新为空、失败或文件损坏时保留原稳定池，成功结果原子替换；启用后在证据临近过期时自动刷新；
- 停用会先取消并等待正在执行的刷新，再把新增清单改名保留，不删除稳定隧道。

在集成控制台的“代理资源 → 免费验证池”中手动首次启用。免费公共代理由未知第三方运营，可能记录或篡改未加密流量，不得用于账号、支付或隐私数据。

以上系统均以 root 执行同一段命令，自动选择 APT 或 DNF：

```sh
if command -v apt-get >/dev/null; then apt-get update && apt-get install -y ca-certificates curl; else dnf -y install ca-certificates && { command -v curl >/dev/null || dnf -y install curl; }; fi &&
curl -fsSL https://raw.githubusercontent.com/hanhaoops/xnvgatebox/v0.9.6/vps/install.sh -o /tmp/xnvgatebox-install.sh && bash /tmp/xnvgatebox-install.sh --version v0.9.6 && xnvgatebox access
```

安装完成后显示随机生成的管理地址和密码。之后可随时查看：

```sh
xnvgatebox access
```

在浏览器打开管理地址并登录。防火墙需放行管理端口（默认 `8899`）及实际使用的接入端口；系统和服务商的防火墙都需检查。

CentOS 首次安装会编译 SSTP 客户端，耗时和内存需求高于 Debian / Ubuntu，请等待依赖安装与构建完成。

首次安装默认创建并开启本机直出，可直接导入订阅；已有安装的开关和客户端身份保留。VPN Gate 来源暂不可达时仍可完成安装并登录，候选由后台或定时器获取；也可添加第三方 SOCKS5。VPN Gate 出口等待候选，不自动回落直出。

第三方镜像后备默认开启，可在候选页的「来源设置」关闭；已有明确保存的关闭选择保留。仍由自己的 VPS 优先请求原来源，失败后下载并校验镜像原始 CSV，再自行检测节点与真实出口；不采用镜像的检测结论。页面区分本机获取时间和镜像声明的抓取时间。详见 [候选来源](docs/POOL_SOURCE_FALLBACK.md)。

## 首次使用

1. 刷新候选
2. 等待就绪
3. 复制订阅
4. 导入使用

可先用默认的“VPS 本机直出”测试客户端接入。未设置数量且无旧 Slot 时，取得候选后自动创建 16 个 VPN Gate 出口并按当前并发连接，无需先设置数量或检测全部候选；已有数量（含 0）和旧出口保留。可按需调整数量或添加自己的 SOCKS5，出口就绪后更新客户端订阅。候选刷新显示等待时间、完成结果和上次成功获取时间。详细操作见 [首次使用](docs/FIRST_USE.md)。

「候选节点 → 周期任务」可分别设置来源刷新和候选检测，默认每 60 分钟一次，最低 30 分钟，也可关闭；检测沿用用户设置的并发。同一自动任务不重叠，刷新失败保留旧候选。所有获取与检测均由自己的 VPS 执行。

使用 Clash Verge 时，在「我的订阅」选择 Clash/Mihomo 格式再复制链接；v2rayN 保持默认格式。无需第三方订阅转换服务，详见 [周期任务与订阅格式](docs/SCHEDULE_AND_CLASH.md)。

## 更新

在网页“设置 → 版本与更新”检查并安装正式版，或执行：

```sh
xnvgatebox check-update
xnvgatebox update
xnvgatebox update-status
```

更新会短暂中断连接，保留已有管理地址、密码、订阅和出口设置。安装包经过 SHA256 及成员清单校验，更新前保存本项目备份；失败时尝试恢复原部署。备份位于 `/var/backups/xnvgatebox/`，重装系统前请另存。详见 [安装与更新](docs/INSTALL_UPDATE.md) 和 [备份与恢复](docs/BACKUP_REINSTALL.md)。

## 卸载

```sh
xnvgatebox uninstall
```

默认保留备份。需要同时删除备份和可确认归属的旧版文件时，先预览再执行：

```sh
xnvgatebox uninstall --dry-run --purge --legacy
xnvgatebox uninstall --purge --legacy
```

卸载需确认，不移除其他程序或共享系统依赖。旧版本用法见 [卸载说明](docs/UNINSTALL.md)。

## 使用须知

- VPN Gate 节点由志愿者提供，可用数量和国家随时变化；候选数量不等于可用出口数。
- VPN Gate 或自定义代理故障时，对应连接阻断，不会自动改用 VPS 本机直出。
- 国家与住宅类型分别判断。`unknown` 表示类型未知，不能视为已验证住宅 IP；手填国家、城市和备注不是检测证据。
- VPS 转发的订阅和 SOCKS5 需要 VPS 持续运行；原始 SSTP 导出需消费端自行支持相应协议。
- 管理地址、订阅和备份含私密信息，请妥善保存。公网管理建议使用 HTTPS 反向代理或 SSH 转发。
- 当前代理链路面向 TCP / IPv4，不提供未经验证的 UDP、IPv6 或 XHTTP 支持。

## 文档

[首次使用](docs/FIRST_USE.md) · [控制台](docs/CONSOLE.md) · [第三方 SOCKS5](docs/THIRD_PARTY_SOCKS.md) · [原始 SSTP](docs/SSTP_USAGE.md) · [安装更新](docs/INSTALL_UPDATE.md) · [开发与测试](docs/TESTING.md)

核心工具采用 [GPL-3.0-only](LICENSE)。独立 EdgeTunnel 修改采用 GPL-2.0-only；依赖许可、上游来源及复用边界见 [THIRD_PARTY.md](THIRD_PARTY.md)。
