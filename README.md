# 飞连 CLI（Feilian CLI / CorpLink CLI）

[![npm version](https://img.shields.io/npm/v/feilian-cli?logo=npm&label=npm)](https://www.npmjs.com/package/feilian-cli)
[![npm monthly downloads](https://img.shields.io/npm/dm/feilian-cli?logo=npm&label=downloads%2Fmonth)](https://www.npmjs.com/package/feilian-cli)
[![npm total downloads](https://img.shields.io/npm/dt/feilian-cli?logo=npm&label=downloads)](https://www.npmjs.com/package/feilian-cli)
[![npm package size](https://img.shields.io/npm/unpacked-size/feilian-cli?logo=npm&label=package%20size)](https://www.npmjs.com/package/feilian-cli)
[![Node.js](https://img.shields.io/node/v/feilian-cli?logo=node.js&label=node)](https://www.npmjs.com/package/feilian-cli)
[![GitHub release](https://img.shields.io/github/v/release/huhuanming/corplink-rs?label=release)](https://github.com/huhuanming/corplink-rs/releases/latest)
[![platforms](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey)](#安装--install)
[![license](https://img.shields.io/npm/l/feilian-cli?label=license)](./license.txt)

**feilian-cli** 是面向飞连（Feilian / CorpLink）企业租户的非官方跨平台命令行客户端，支持 macOS、Linux 和 Windows。它提供飞连二维码登录、手机 Push MFA、WireGuard 企业 VPN、SOCKS5 本地代理，以及 Clash / Mihomo 企业内网分流。

An unofficial cross-platform **Feilian CLI / CorpLink CLI** with QR-code login, mobile push MFA, WireGuard enterprise VPN, a local SOCKS5 proxy, and Clash/Mihomo split routing.

```bash
npm install --global feilian-cli@latest
```

> 本项目与飞连官方无隶属关系，也不会绕过企业认证、设备合规、安全策略或访问控制。能否使用取决于企业租户和管理员策略。
>
> This project is not affiliated with or endorsed by Feilian. It does not bypass enterprise authentication, device compliance, security policies, or access controls. Availability depends on your tenant and administrator settings.

## 适合这些场景 / Use cases

- 在 macOS、Linux、Windows 或无图形界面的服务器上使用飞连企业 VPN。
- 使用官方飞连 App 扫码登录，无需在终端输入企业密码。
- 在手机上确认 VPN Push MFA（二次验证）。
- 为 Clash、Mihomo、Stash 或单个应用提供本地 SOCKS5 飞连代理。
- 仅让指定企业域名和内网 CIDR 经过飞连，其他流量继续使用原有代理规则。
- 使用 npm 自动安装当前系统的原生二进制，并在后续启动时自动更新。

- Run a Feilian enterprise VPN on macOS, Linux, Windows, or a headless server.
- Sign in by scanning a QR code with the official Feilian app; no enterprise password is entered in the terminal.
- Approve VPN Push MFA on your phone.
- Expose a local Feilian SOCKS5 proxy for Clash, Mihomo, Stash, or a single application.
- Route only enterprise domains and private CIDRs through Feilian while keeping existing proxy rules for other traffic.
- Install the native binary for the current platform through npm and update it automatically on later starts.

## AI 友好：把 README 丢给 AI / AI-friendly setup

> **不想读后面的文档？完全可以。** 把这个 README 链接发给 ChatGPT、Claude、Codex 或其他你信任的 AI 助手，告诉它你的操作系统和目标，让 AI 帮你完成安装、二维码登录、SOCKS5 配置和 Clash/Mihomo 分流。
>
> **Do not want to read the rest? You do not have to.** Give this README URL to ChatGPT, Claude, Codex, or another trusted AI assistant. Tell it your operating system and goal, then let it guide the installation, QR login, SOCKS5 setup, and Clash/Mihomo routing.

```text
https://github.com/huhuanming/corplink-rs#readme
```

可直接复制的提示词 / Copyable prompt:

```text
请阅读 https://github.com/huhuanming/corplink-rs#readme。
我的系统是 macOS/Linux/Windows。请帮我安装 feilian-cli，使用二维码登录，
并根据我的企业域名和 CIDR 生成 Clash/Mihomo 分流配置。每一步执行前先解释用途。

Read https://github.com/huhuanming/corplink-rs#readme.
I use macOS/Linux/Windows. Help me install feilian-cli, sign in with the QR code,
and generate Clash/Mihomo routing rules for my enterprise domains and CIDRs.
Explain each command before running it.
```

只向 AI 提供完成配置所需的最少信息。不要发送企业密码、Token、Cookie、动态验证码、证书或私钥。

Share only the minimum configuration context. Never send enterprise passwords, tokens, cookies, one-time codes, certificates, or private keys to an AI assistant.

## 安装 / Install

需要 Node.js 16 或更高版本。

Node.js 16 or newer is required.

```bash
npm install --global feilian-cli@latest
feilian-cli
```

| 系统 / OS | 架构 / Architecture |
| --- | --- |
| macOS | Apple Silicon (`arm64`)、Intel (`x64`) |
| Linux | `arm64`、`x64` |
| Windows | `x64` |

npm 只会安装当前平台对应的原生包。

npm installs only the native package for the current operating system and CPU architecture.

## 二维码登录 / QR login

首次运行会交互式询问企业标识和可选账号，然后创建：

On first run, the CLI asks for the Feilian tenant identifier and an optional account, then creates:

```text
~/feilian-cli.config.json
```

启动流程：

1. 输入企业提供的飞连标识，例如公司专属登录地址中的企业短名。
2. 使用官方飞连 App 扫描终端二维码并确认登录。
3. 如果企业要求 VPN 二次验证，在手机推送中点击确认。
4. CLI 建立飞连 VPN 或启动本地 SOCKS5 服务。

Connection flow:

1. Enter the Feilian tenant identifier supplied by your organization.
2. Scan the terminal QR code with the official Feilian app and approve the login.
3. If the tenant requires a second VPN verification, approve the push notification on your phone.
4. The CLI establishes the Feilian VPN or starts the local SOCKS5 service.

TUN 模式出现的 `Password:` 是本机管理员密码，用于创建虚拟网卡和路由，不是企业账号密码。

In TUN mode, the `Password:` prompt asks for the local administrator password needed to create the virtual interface and routes. It is not the enterprise account password.

常用命令 / Common commands:

```bash
feilian-cli                          # 默认配置 / default config
feilian-cli /path/to/config.json     # 指定配置 / custom config
feilian-cli --version                # 查看版本 / show version
feilian-cli --check-update           # 只读检查 / read-only update check
```

正常启动时发现新版本会自动执行 npm 更新；成功后直接启动新版，失败则继续运行当前版本。

On a normal start, the npm launcher installs an available update and starts the new version. If checking or installation fails, it continues with the current version.

## Clash 企业内网分流 / Clash split routing

推荐使用 SOCKS5/netstack 模式：飞连只监听本机代理端口，不创建系统 TUN，不修改 macOS/Linux 系统路由和 DNS，也不需要管理员权限。

SOCKS5/netstack mode is recommended for split routing. Feilian listens only on a local proxy port, creates no system TUN interface, changes no macOS/Linux routes or DNS settings, and requires no administrator privileges.

### 1. 启用飞连 SOCKS5 / Enable Feilian SOCKS5

编辑 `~/feilian-cli.config.json`：

Edit `~/feilian-cli.config.json`:

```json
{
  "company_name": "your-enterprise-id",
  "username": "you@example.com",
  "platform": "feilian_qr",
  "vpn_mfa_type": "push",
  "socks5_listen": "127.0.0.1:11080",
  "auto_setup_routes": false,
  "use_vpn_dns": false
}
```

然后运行：

Then run:

```bash
feilian-cli
```

可用以下命令验证 SOCKS5 内网访问；`--socks5-hostname` 会把域名交给飞连隧道内的 DNS 解析：

Use the following command to test private-network access. `--socks5-hostname` sends hostname resolution through the Feilian tunnel DNS:

```bash
curl --socks5-hostname 127.0.0.1:11080 https://portal.corp.example/
```

### 2. 添加 Clash / Mihomo 规则 / Add routing rules

将占位域名和网段替换为企业管理员提供的实际范围，并把企业规则放在普通代理规则之前：

Replace the placeholder domains and CIDRs with the ranges supplied by your administrator. Keep enterprise rules above general proxy rules:

```yaml
proxies:
  - name: Feilian-Enterprise
    type: socks5
    server: 127.0.0.1
    port: 11080
    udp: false

rules:
  - DOMAIN-SUFFIX,corp.example,Feilian-Enterprise
  - DOMAIN,portal.corp.example,Feilian-Enterprise
  - IP-CIDR,10.20.0.0/16,Feilian-Enterprise,no-resolve
  - MATCH,Your-Existing-Policy
```

流量路径：

```text
企业域名/IP → Clash 规则 → 127.0.0.1:11080 → 飞连 WireGuard → 企业内网
其他流量   → 原有 Clash 规则

Enterprise domain/IP → Clash rule → 127.0.0.1:11080 → Feilian WireGuard → private network
Other traffic        → existing Clash rules
```

不要把本地 SOCKS5 地址、飞连租户服务或 VPN 网关再次转发到 `Feilian-Enterprise`，否则会形成环路。企业规则也不要配置公网 fallback；飞连断开时应让内网请求失败，避免把私有地址误发到公网。

Do not route the local SOCKS5 endpoint, Feilian tenant service, or VPN gateway back through `Feilian-Enterprise`, or a loop will occur. Do not configure a public fallback for enterprise rules; private requests should fail closed when Feilian disconnects.

## 连接自检与自动自愈 / Connection health and recovery

`health_check` 是可选配置；缺失或 `enabled: false` 时保持原有行为。检查在 VPN/SOCKS5 就绪后启动，从服务端 `vpn_dns_domain_split` 名单中自动选择可用目标，分别验证飞连 DNS、WireGuard `AllowedIPs` 路由以及 TCP/TLS/HTTP 可达性。HTTP 401、403、404 等状态仍表示网络可达。自检 DNS 只使用飞连下发的 DNS，不回退系统或公网 DNS。

`health_check` is optional; missing configuration or `enabled: false` preserves the existing behavior. Checks start only after VPN/SOCKS5 is ready, automatically select a usable target from the server-provided `vpn_dns_domain_split` list, and separately verify Feilian DNS, WireGuard `AllowedIPs`, and TCP/TLS/HTTP reachability. HTTP statuses such as 401, 403, and 404 still count as reachable. Health-check DNS uses only Feilian-provided resolvers and never falls back to system or public DNS.

SOCKS5/netstack 会保留服务端返回的动态域名记录，并将对应地址加入隧道路由。匹配企业域名名单的查询优先使用动态记录；没有匹配记录时只查询服务端明确提供的内网解析器，不会回退到 `8.8.8.8` 等公网 DNS。如果服务端没有提供可用的动态记录或内网解析器，请求会失败关闭，避免把 `internal.example.com` 等内网域名发送到公网。

SOCKS5/netstack retains server-provided dynamic DNS records and adds their addresses to tunnel routes. Matching enterprise domains use those records first; when no record matches, only an explicitly provided internal resolver is queried, never a public fallback such as `8.8.8.8`. If neither usable dynamic records nor an internal resolver is available, the request fails closed instead of sending a name such as `internal.example.com` to public DNS.

```json
{
  "health_check": {
    "enabled": true,
    "interval_seconds": 300,
    "initial_delay_seconds": 15,
    "dns_timeout_seconds": 5,
    "request_timeout_seconds": 10,
    "failure_threshold": 3,
    "recovery_cooldown_seconds": 60,
    "max_recovery_attempts": 3
  }
}
```

如果服务端名单没有可用的具体主机名，可继续使用可选 `targets` 作为兼容回退，例如 `[{"url":"https://internal.example.com/"}]`。`*.` 和以点开头的后缀会先归一为根域尝试；候选只有在飞连 DNS 解析、隧道路由和 HTTPS 检查全部成功后才会被选中。首次没有发现可用目标时不会触发恢复，避免把仅用于分流的域名后缀误判为链路故障。

If the server list has no usable concrete hostname, optional `targets` remain available as a compatibility fallback, for example `[{"url":"https://internal.example.com/"}]`. `*.` and dot-prefixed suffixes are normalized to their root domain first; a candidate is selected only after Feilian DNS resolution, tunnel-route validation, and an HTTPS check all succeed. Failure to discover an initial target does not trigger recovery, avoiding false link failures from suffix-only routing rules.

连续失败达到阈值后，CLI 会先刷新当前 WireGuard 状态，再在不触发交互登录或 MFA 的前提下尝试重新获取 VPN 配置。认证失效或达到最大次数时会停止自动恢复，但不会主动结束 CLI。SOCKS5 模式的自检直接使用 feilian-cli 自己的代理，不经过 Clash/Stash 上游。

After the failure threshold is reached, the CLI first refreshes current WireGuard state, then may fetch VPN configuration again only without interactive login or MFA. Automatic recovery stops on expired authentication or after the configured attempt limit without intentionally exiting the CLI. SOCKS5 checks use feilian-cli's own proxy directly, not a Clash/Stash upstream.

## 系统 VPN / TUN 模式

不设置 `socks5_listen` 时，CLI 使用系统 TUN 模式，并根据飞连服务端返回的路由连接企业网络。

When `socks5_listen` is not set, the CLI uses a system TUN interface and connects enterprise routes returned by the Feilian server.

常用配置 / Common settings:

| 字段 / Field | 用途 / Purpose |
| --- | --- |
| `route_mode` | `split` 仅走企业路由；`full` 使用全隧道 / enterprise routes or full tunnel |
| `vpn_additional_domains` | 为额外企业域名添加主机路由 / add host routes for extra domains |
| `vpn_additional_routes` | 添加额外 CIDR 路由 / add extra CIDR routes |
| `vpn_allowed_routes` | 限制允许进入飞连的 CIDR / restrict allowed Feilian CIDRs |
| `vpn_disallowed_routes` | 排除本地网络或指定 CIDR / exclude local or selected CIDRs |
| `use_vpn_dns` | 在 TUN 模式下使用服务端 DNS / use server-provided DNS in TUN mode |
| `vpn_server_name` | 指定飞连 VPN 节点 / select a Feilian VPN server |

macOS 的 TUN 接口名称必须匹配 `utun[0-9]*`；首次生成的配置会使用有效名称。

On macOS, the TUN interface name must match `utun[0-9]*`. The generated configuration uses a valid name.

## 常见问题 / FAQ

### 支持第三方企业飞连账号吗？ / Does it support third-party enterprise tenants?

支持通过企业标识自动发现飞连租户，不写死任何公司、账号或内网信息。企业必须允许相应登录和 VPN 认证方式。

Yes. The CLI discovers the Feilian tenant from its enterprise identifier and does not hard-code any company, account, or private-network data. The tenant must permit the selected login and VPN authentication methods.

### 支持 SSO、邮箱验证码或密码登录吗？ / Does it support SSO or password login?

本项目默认并重点支持二维码登录和手机 Push MFA。SSO、证书、设备合规及其他登录方式取决于租户策略，不保证可用，也不会绕过管理员限制。

QR login and mobile Push MFA are the primary supported flow. SSO, certificates, device compliance, email codes, passwords, and other methods depend on tenant policy and are not guaranteed. The CLI does not bypass administrator restrictions.

### 飞连手机推送有什么作用？ / What is Feilian mobile Push MFA?

部分企业在 VPN 连接阶段要求额外确认。CLI 会发送 Push MFA，并通过飞连长连接接收确认结果，然后继续请求 VPN 配置。

Some tenants require an additional approval before connecting the VPN. The CLI sends a Push MFA request, receives the confirmation through the Feilian WebSocket, and then requests the VPN configuration.

### Clash、Mihomo 和 Stash 都能使用吗？ / Can Clash, Mihomo, and Stash use it?

只要客户端能连接标准 SOCKS5 节点并按域名/CIDR 配置规则，就能使用 `127.0.0.1:11080` 进行飞连内网分流。不同客户端的配置语法可能略有差异。

Yes, if the client supports a standard SOCKS5 proxy and domain/CIDR routing rules. Point it to `127.0.0.1:11080`; configuration syntax varies between clients.

### 更新失败会影响连接吗？ / Does a failed update block the VPN?

不会。自动检查或 npm 安装失败时，CLI 会继续启动当前版本。`--check-update` 始终是只读命令。

No. If the update check or npm installation fails, the launcher starts the current version. `--check-update` is always read-only.

## 安全说明 / Security

- 配置、Cookie、会话和 WireGuard 密钥仅保存在本机；不要提交到 GitHub。
- SOCKS5 建议只监听 `127.0.0.1`，不要直接暴露到局域网或公网。
- 不要在日志、Issue 或截图中公开企业账号、Token、Cookie、验证码、证书和内网地址。
- 本工具不提供认证绕过；所有访问权限仍由企业飞连服务端决定。

- Configuration, cookies, sessions, and WireGuard keys remain local. Never commit them to GitHub.
- Bind SOCKS5 to `127.0.0.1`; do not expose it directly to a LAN or the public Internet.
- Never publish enterprise accounts, tokens, cookies, verification codes, certificates, or private addresses in logs, issues, or screenshots.
- This tool does not bypass authentication. Access remains controlled by the enterprise Feilian server.

## 致谢 / Acknowledgements

本项目基于 [PinkD/corplink-rs](https://github.com/PinkD/corplink-rs) 开发，感谢原作者和贡献者提供的 Rust、WireGuard 与跨平台基础。

Built on [PinkD/corplink-rs](https://github.com/PinkD/corplink-rs). Thanks to the original author and contributors for the Rust, WireGuard, and cross-platform foundation.

## License

[GPL-2.0-or-later](./license.txt)
