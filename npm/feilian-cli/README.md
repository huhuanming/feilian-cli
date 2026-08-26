# feilian-cli

一个面向飞连（Feilian / CorpLink）企业租户的非官方跨平台命令行客户端：输入企业标识、扫描二维码、在飞连手机 App 中确认登录与 VPN 二次验证，即可建立企业网络连接，并可通过本地 SOCKS5 节点交给 Clash 精确分流。

An unofficial cross-platform CLI for Feilian/CorpLink enterprise tenants. Enter the enterprise identifier, scan a QR code, approve login and VPN verification in the Feilian mobile app, then connect directly or expose a local SOCKS5 endpoint for precise Clash routing.

> 本项目是社区实现，与飞连官方无隶属关系，也未获得官方背书。它不会绕过企业认证、安全策略或访问控制。实际可用能力取决于企业租户的飞连版本和管理员策略。
>
> This is an independent community project. It is not affiliated with or endorsed by Feilian. It does not bypass enterprise authentication, security policies, or access controls. Availability depends on the tenant's Feilian version and administrator policy.

## 为什么使用 / Why use it

- **第三方企业租户登录**：输入企业提供的飞连标识，CLI 自动发现对应服务；代码和 npm 包不写死任何公司、账号或内网信息。
- **二维码登录**：默认生成二维码，使用官方飞连手机 App 扫码并确认，无需在终端输入企业密码。
- **手机推送二次验证**：连接 VPN 时接收企业要求的 Push MFA，在手机上点击确认后继续连接。
- **Clash 精确分流**：使用纯用户态 SOCKS5 模式，只把企业域名或 CIDR 交给飞连，其他流量继续使用原有 Clash 规则。
- **标准 VPN 与精细路由**：支持 TUN、服务端下发路由、split/full 模式，以及额外域名、CIDR 白名单和排除路由。
- **跨平台按需安装**：一个 npm 主包覆盖 macOS、Linux 和 Windows；npm 只下载当前系统对应的原生二进制。
- **自动安装更新**：正常启动时发现新版本会通过 npm 自动安装并直接启动新版；检查或安装失败不影响当前版本运行。

- **Third-party enterprise tenant login**: enter the Feilian identifier supplied by your organization and let the CLI discover the tenant service. No company, account, or private-network data is hard-coded in the package.
- **QR-code login**: scan the terminal QR code with the official Feilian mobile app. No enterprise password needs to be typed into the terminal.
- **Mobile push MFA**: approve the VPN verification notification on your phone, then the CLI continues through the tenant's authorized connection flow.
- **Precise Clash routing**: expose a userspace SOCKS5 endpoint and send only enterprise domains or CIDRs through Feilian while preserving existing Clash rules for everything else.
- **VPN and detailed routing controls**: TUN mode, server-provided routes, split/full routing, additional domains and CIDRs, allowlists, and excluded routes.
- **One package, native per-platform install**: macOS, Linux, and Windows are supported; npm installs only the binary for the current OS and CPU.
- **Automatic updates**: on a normal start, an available npm release is installed and the newly installed CLI is started. Check or installation failures do not block the current version.

## 支持的平台 / Supported platforms

| 系统 / OS | 架构 / Architecture |
| --- | --- |
| macOS | Apple Silicon (`arm64`), Intel (`x64`) |
| Linux | `arm64`, `x64` |
| Windows | `x64` |

## 安装 / Install

需要 Node.js 16 或更高版本。

Node.js 16 or newer is required.

```sh
npm install --global feilian-cli@latest
```

确认安装版本：

Verify the installed version:

```sh
feilian-cli --version
```

## 更新日志 / Changelog

### 1.0.4 — 2026-08-26

- 修复 SOCKS5/netstack 内网域名解析：保留服务端动态域名记录并自动加入隧道路由；企业域名只使用动态记录或服务端内网解析器，不再回退到 `8.8.8.8` 等公网 DNS。
- DNS 与 WireGuard/netstack 状态可在自动恢复时原地刷新，不替换现有 SOCKS5 监听器；没有可用内网解析路径时会安全失败。

- Fixed private-domain resolution in SOCKS5/netstack mode. Server-provided dynamic records are retained and routed through the tunnel; enterprise domains use only those records or an internal resolver, never a public fallback such as `8.8.8.8`.
- DNS and WireGuard/netstack state can now refresh in place during recovery without replacing the SOCKS5 listener. Requests fail closed when no internal resolution path is available.

### 1.0.3 — 2026-08-26

- 增加连接自检与有限自动自愈，区分 DNS、隧道路由、TCP/TLS 和 HTTP 可达性；HTTP 401、403、404 仍视为链路可达。
- 登录后自动从服务端域名名单选择健康检查候选，默认每 5 分钟检查；认证失效、限流或超过恢复次数时停止自动重试。

- Added connection health checks and bounded recovery across DNS, tunnel routing, TCP/TLS, and HTTP reachability. HTTP 401, 403, and 404 responses still count as reachable.
- Health targets are selected automatically from the server-provided domain list after login and checked every five minutes by default. Automatic retries stop on expired authentication, rate limiting, or the recovery-attempt limit.

## 首次使用 / First run

```sh
feilian-cli
```

首次运行的完整流程：

1. 输入企业提供的飞连标识，例如管理员给出的企业短名称；这不是企业显示名称，也不是服务器 URL。
2. 可选输入企业账号或邮箱，便于保存本地配置；默认二维码流程通常不要求终端输入企业密码。
3. CLI 在用户主目录创建 `feilian-cli.config.json`，Unix 系统上权限仅限当前用户。
4. 使用官方飞连手机 App 扫描终端中的二维码，并在手机上确认登录。
5. 如果企业为 VPN 启用了二次认证，手机会收到飞连确认推送；点击确认后 CLI 继续建立连接。
6. 保持进程运行。使用 `Ctrl-C` 可断开并执行清理。

Complete first-run flow:

1. Enter the Feilian enterprise identifier supplied by your organization. This is normally a short tenant code, not the company display name or a server URL.
2. Optionally enter the enterprise account or email for the local configuration. The default QR flow normally does not ask for an enterprise password in the terminal.
3. The CLI creates `feilian-cli.config.json` in the user home directory, with user-only permissions on Unix.
4. Scan the terminal QR code with the official Feilian mobile app and approve the login.
5. If the tenant requires VPN MFA, approve the Feilian push notification on the phone. The CLI then continues establishing the connection.
6. Keep the process running. Press `Ctrl-C` to disconnect and run cleanup.

> 在 macOS/Linux 的 TUN 模式中，系统可能提示输入本机管理员密码，以创建虚拟网卡和路由。这是本机 `sudo` 密码，不是飞连企业账号密码。用户态 SOCKS5 模式不创建系统 TUN，通常不需要管理员权限。
>
> In TUN mode on macOS/Linux, the operating system may request the local administrator password to create the virtual interface and routes. This is the local `sudo` password, not the Feilian enterprise password. Userspace SOCKS5 mode does not create a system TUN and normally does not require administrator privileges.

## 两种运行方式 / Two connection modes

### 1. 系统 VPN/TUN / System VPN/TUN

默认配置使用企业下发的路由并创建系统虚拟网卡，适合希望应用直接访问企业内网的场景。

The default configuration creates a system tunnel and applies tenant-provided routes, suitable when applications should access enterprise resources directly.

```json
{
  "company_name": "your-enterprise-id",
  "username": "you@example.com",
  "platform": "feilian_qr",
  "vpn_mfa_type": "push",
  "route_mode": "split",
  "auto_setup_routes": true,
  "use_vpn_dns": false
}
```

### 2. Clash + 用户态 SOCKS5 / Clash + userspace SOCKS5

在配置中加入 `socks5_listen` 后，CLI 使用用户态网络栈并暴露本地 SOCKS5 代理，不创建系统 TUN、系统路由或系统 DNS。此模式目前支持 TCP `CONNECT`，很适合由 Clash 按企业域名/IP 选择性转发。

Set `socks5_listen` to use the userspace network stack and expose a local SOCKS5 proxy without creating a system TUN, routes, or DNS settings. This mode currently supports TCP `CONNECT` and is ideal when Clash should forward only selected enterprise domains/IPs.

`~/feilian-cli.config.json` 示例：

Example `~/feilian-cli.config.json`:

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

Clash 配置示例（请将占位域名和网段替换为企业管理员提供的实际范围）：

Clash example (replace the placeholder domain and CIDR with ranges supplied by the enterprise administrator):

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
  # Keep the rest of your existing Clash rules below these enterprise rules.
  - MATCH,Your-Existing-Policy
```

要点：

- 企业规则应放在普通代理规则之前。
- 域名规则会把域名交给 SOCKS5 连接流程；IP 规则建议加 `no-resolve`。
- 不要把 `127.0.0.1:11080`、飞连企业服务端或 VPN 网关再次转发到 `Feilian-Enterprise`，否则可能形成环路。
- 飞连 CLI 断开时，Clash 会发现 SOCKS5 节点不可用，企业请求会失败，而不是自动落到公网；不要为企业规则配置公网 fallback。

Important notes:

- Place enterprise rules before general proxy rules.
- Domain rules pass hostnames into the SOCKS5 connection flow; add `no-resolve` to IP rules.
- Never route `127.0.0.1:11080`, the Feilian tenant endpoint, or the VPN gateway back to `Feilian-Enterprise`, or a loop may occur.
- When the CLI disconnects, Clash sees the SOCKS5 node as unavailable and enterprise requests fail instead of silently falling back to the public internet. Do not configure a public fallback for enterprise rules.

## 配置与命令 / Configuration and commands

默认配置位置：

Default configuration path:

```text
~/feilian-cli.config.json
```

也可以使用指定配置：

Run with an explicit configuration file:

```sh
feilian-cli /path/to/config.json
```

检查更新：

Check for an update:

```sh
feilian-cli --check-update
```

该命令只报告版本状态，不会执行安装。正常启动 `feilian-cli` 时才会自动安装可用更新，并在成功后直接启动新版。

This command only reports version status and never installs anything. Automatic installation runs only during a normal `feilian-cli` start, and starts the new version after a successful update.

升级到最新版：

Upgrade to the latest release:

```sh
npm install --global feilian-cli@latest
```

## 企业兼容性 / Enterprise compatibility

本项目面向使用飞连/CorpLink 的企业租户，不限制为某一家企业。企业必须允许二维码登录，并在需要时启用飞连 App Push MFA。SSO、设备合规、证书、风控或其他管理员策略仍由企业服务端决定；如果企业只允许官方桌面客户端，本 CLI 不能绕过该限制。

This project targets Feilian/CorpLink enterprise tenants and is not tied to one organization. The tenant must permit QR login and, when required, Feilian app push MFA. SSO, device compliance, certificates, risk controls, and other administrator policies remain server-enforced. If a tenant allows only the official desktop client, this CLI cannot bypass that restriction.

## 安全与隐私 / Security and privacy

- npm 包不包含企业名称、账号、Cookie、Token、证书、私钥或内网域名。
- 登录会话和生成的配置保存在本机，请像保护企业 VPN 凭据一样保护它们。
- 不要把 `feilian-cli.config.json`、Cookie 文件、日志中的敏感字段或动态验证码提交到 GitHub。
- 建议只监听本机地址（例如 `127.0.0.1:11080`）；除非明确配置了认证和防火墙，否则不要把 SOCKS5 暴露到局域网或公网。

- The npm package contains no enterprise name, account, cookie, token, certificate, private key, or internal domain.
- Login sessions and generated configuration stay on the local machine and should be protected like enterprise VPN credentials.
- Never commit `feilian-cli.config.json`, cookie files, sensitive log fields, or one-time codes to GitHub.
- Prefer a loopback listener such as `127.0.0.1:11080`. Do not expose SOCKS5 to a LAN or the internet without deliberate authentication and firewall controls.

## 致谢 / Acknowledgements

本项目 fork 自 [PinkD/corplink-rs](https://github.com/PinkD/corplink-rs)。感谢原作者 PinkD、上游维护者和所有贡献者完成了 Rust 客户端、WireGuard、路由与跨平台支持。此 fork 在上游基础上增加了 npm 分平台发布、交互式企业配置、飞连二维码登录、手机 Push MFA，以及便于 Clash 分流的用户态 SOCKS5 使用流程。

This project is forked from [PinkD/corplink-rs](https://github.com/PinkD/corplink-rs). Many thanks to PinkD, the upstream maintainers, and every contributor for the Rust client, WireGuard integration, routing, and cross-platform foundation. This fork adds per-platform npm distribution, interactive enterprise setup, Feilian QR login, mobile push MFA, and a userspace SOCKS5 workflow designed for Clash split routing.

## 项目与许可证 / Project and license

源码、问题反馈和构建说明：<https://github.com/huhuanming/corplink-rs>

Source, issue tracker, and build instructions: <https://github.com/huhuanming/corplink-rs>

License: GPL-2.0-or-later.
