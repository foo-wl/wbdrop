# WBDrop

两台**物理隔离**的电脑（MAC/WIN）之间的点对点文件传输工具。单文件、免安装、无第三方依赖。

一根网线（或一个 Wi-Fi 软 AP）+ 一个可执行文件，30 MB 文件 0.3 秒传完，双向 HMAC 签名鉴权，全程不出网。

```
拖文件进浏览器窗口 → 松手 → 对端落盘。没有「开始发送」按钮，没有每次输入 IP。
```

**实测**（v2 双实例联调）：30 MB / 0.29 秒 / 102.6 MB/s，SHA-256 前后一致。

---

## 为什么快

不走任何现有网络。两台机器之间拉一根网线，各自获得 `169.254.x.x` 链路本地地址，形成一个只存在于这两台机器之间的孤立网段——没有网关、没有 DNS、没有路由转发。

| 方式 | 30 MB 耗时 | 需要互联网 | 触碰现有网络 | 需要硬件 |
|---|---|---|---|---|
| 蓝牙 OBEX | 2–5 分钟 | 否 | 否 | 否 |
| **WBDrop（Wi-Fi 软 AP）** | 约 1 秒（链路切换另需 10 秒） | 否 | 否 | 否 |
| **WBDrop（网线直连）** | **约 0.3 秒**（百兆约 3 秒） | 否 | 否 | 一根网线 |
| 移动硬盘摆渡 | 约 1–2 分钟（含插拔） | 否 | 否 | 是 |

## 特性

- **单文件**：前端用 `//go:embed` 打进二进制，双击即用，卸载就是删文件；Windows 免安装、macOS 免 kext。
- **零依赖**：只用 Go 标准库，不拉第三方包，没有运行时要装。
- **只绑一块网卡**：双监听 = `127.0.0.1`（本机 UI）+ 用户显式选中的直连地址，**永不使用 `0.0.0.0`**。
- **双向鉴权**：对端请求须带 `HMAC-SHA256(配对码, method + path + 时间戳)`，时间窗 ±300 秒。
- **流式传输**：上传流直接转发给对端，本机不落临时文件、不整文件进内存，常数内存占用。

## 快速开始

### 1. 拿可执行文件

从 [Releases](https://github.com/foo-wl/wbdrop/releases) 下载对应平台的产物：

| 文件 | 平台 |
|---|---|
| `wbdrop-windows-amd64.exe` | Windows 10/11 x64 |
| `wbdrop-macos-amd64` | macOS Intel（x86_64） |
| `wbdrop-macos-arm64` | macOS Apple Silicon |

也可自行编译，见 [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)。macOS 从浏览器下载的文件没有执行位，首次运行前：

```bash
chmod +x wbdrop-macos-arm64
xattr -d com.apple.quarantine wbdrop-macos-arm64   # 绕过 Gatekeeper 隔离
```

### 2. 建一条只有两台机器能看到的链路

二选一，详细步骤（含硬件选型、静态 IP 场景、防火墙放行）见 **[docs/SETUP.md](docs/SETUP.md)**：

- **方式 A · Wi-Fi 软 AP**：Windows 开一个不带 ICS 的 hosted network，Mac 连上去。纯软件，但 Mac 传输期间无法上互联网。
- **方式 B · 网线直连**：一根网线插两台机器，零配置（DHCP）或两端各跑一个脚本（静态 IP）。无射频痕迹，Mac 不断网。

> 链路本身能 ping 通、能 telnet 到 18432 就够了，WBDrop 不关心它是怎么建起来的。

### 3. 首次配置，之后只管拖文件

1. 两端各运行一次，自动打开 `http://localhost:18432`。
2. 「设置」里确认「直连网卡」不是空的；记下**本机配对码**，告诉对方。
3. 「添加对端」填别名 + 对方 IP + **对方的**配对码，点「保存并测试」，状态灯变绿即可。

之后每次只做一件事：**把文件拖进窗口任意位置**。文件落在对端 `~/Downloads/WBDrop/`。配置持久化在 `~/.wbdrop/config.json`（权限 `0600`），重启不丢。详见 [docs/USAGE.md](docs/USAGE.md)。

## 文档

| 文档 | 内容 |
|---|---|
| [docs/SETUP.md](docs/SETUP.md) | 建链全流程：软 AP / 网线直连、硬件选型、静态 IP 场景、Windows 防火墙放行 |
| [docs/USAGE.md](docs/USAGE.md) | 分发、首次配置、日常使用、配置文件字段、命令行参数 |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | 故障排查：macOS 签名导致的「TCP 通、HTTP EOF」、分层自检、症状速查表 |
| [docs/SECURITY.md](docs/SECURITY.md) | 安全设计：网络边界、应用层防护、加固建议清单 |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | 构建与交叉编译、测试、代码结构、v2 数据流 |

## 适用范围与边界

这个工具解决的是「一台受管控的机器不能装东西、不能上外网，但要往外拿几个文件」这一类问题。它是**传输工具**，不是网络设备：

- 不做 IP 转发、NAT、桥接、代理，不是路由器；不动对端任何网卡配置。
- 不出网、不做 DNS 解析、不访问外部服务器、不检查更新。
- 直连网段内只连这两台机器。**拔掉内网线再插直连线的纪律由使用者保证**，程序无法替你强制。

拿去企业环境用之前，建议把 [docs/SECURITY.md](docs/SECURITY.md) 交给安全 / IT 同事过一遍。

## License

MIT，见 [LICENSE](LICENSE)。仅依赖 Go 标准库，可自由用于商业环境。
