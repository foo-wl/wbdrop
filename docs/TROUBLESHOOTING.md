# 故障排查

排查前先确认版本：设置面板或控制台横幅会显示版本号，**请用 v2.0.5 及以上**。

多数「连不上」不是网络问题，而是 macOS 应用防火墙按代码签名标识拦入站 —— 先看第一节。

---

> **请用 v2.0.5 及以上版本**（设置面板或控制台横幅会显示版本号）。历史修复：v2.0.1 解决空对端列表被序列化成 `null` 导致「保存并测试」静默失败、以及系统代理接管对端请求返回 403；v2.0.2 增加**单向可达检测**；v2.0.3 修复直连网卡掉线后绑定丢失；v2.0.4 放宽探测超时到 8s、只在 `bind` 变化时重建监听器、并返回 `detail` 底层错误原文。
>
> **v2.0.5 修复的是 Mac 端「连不上」的真正根因**：`build.sh` 现在对两个 macOS 产物做 **ad-hoc 代码签名**。未签名的 Go 二进制每次重建都会被 macOS 应用防火墙当成全新程序，旧的「允许传入连接」规则失效，入站连接在 accept 后被直接关闭。详见下一节。

## Mac 端「TCP 通、HTTP 立刻 EOF」：未签名程序被应用防火墙拦入站（v2.0.5 已修）

现象（现场实测）：Windows 能 ping 通 Mac、ARP 学到正确 MAC、`Test-NetConnection 10.20.30.116 -Port 18432 = True`，同一个 IP 上一个**普通 HTTP 服务**从 Windows 也能访问；但 WBDrop 的 `http://10.20.30.116:18432/` 打不开，Go probe = `offline` + `EOF`，.NET 报 `The underlying connection was closed`。同时 Mac→Win 方向完全正常（真实发文件成功），`lsof` 双监听都在、`bind` 正确、`socketfilterfw --getappblocked` 显示 permitted。

**根因：macOS 应用防火墙按代码签名标识管理「允许传入连接」。** Go 交叉编译出的二进制默认完全未签名，每次重新构建都产生新的代码标识，之前加进白名单的规则不再匹配；内核在 accept 后直接关闭连接、不写任何响应字节 —— 于是 TCP 握手成功、HTTP 却是零字节 EOF。`--getappblocked` 只查 plist 里的旧规则，会误报 permitted，这也是「换了新版本还是不行」的原因。

一条命令判定（指向**正在运行**的二进制）：

```bash
PID=$(pgrep -f wbdrop-macos | head -1)
BIN=$(lsof -p "$PID" | awk '$4=="txt"{print $9; exit}')
codesign -dvv "$BIN" 2>&1 | grep -E 'Signature=|not signed'
# 出现 "code object is not signed at all" 就是本问题
```

同一份 v2.0.4 二进制的对照实验（客户端是运行中的 WBDrop 进程，目标 IP 相同，只有服务端副本的签名不同）：

| 服务端副本 | 签名 | probe 结果 |
|---|---|---|
| 原样复制 | 无 | `EOF` / `offline`，`ConnState` 只有 `new → closed`，handler 从未被调用 |
| 同一文件执行 `codesign -s - --force` | adhoc | `state: ok`，`new → active → HANDLER → idle` |

**修复**：v2.0.5 起 `build.sh` 在构建完成后自动执行 `codesign -s - --force`，两个 macOS 产物均带 adhoc 签名，签名失败即报错。**必须换 exe 并重启 Mac 端程序**（规则在进程 exec 时匹配，对运行中的实例补签名无效；首次启动若弹出「允许传入连接」对话框，选允许）。这是构建产物属性，Go 源码无需改动；Windows 没有这套机制，不必为此换版。

已实测排除、不要再去查的项：端口、网段、配对码、时钟差、系统代理、Network Extension（Proxifier / AdGuard 全退后现象不变）、双监听器是否共用 `http.Server`、换 IP 绑到 Wi-Fi、重建直连监听器、macOS 应用防火墙白名单本身。

> **不要用「Mac 本机 curl 自己的直连 IP」当判据。** 受限终端 / AI 代理的 shell 会伪造对 `10.20.30.*` 的连接失败（同一 shell 连 Windows 同样 `000`，而 WBDrop 进程内 probe 却是 `ok`）；据此得出的「网络扩展拦截」「lo0 自连系统行为」结论全是假阳性。可信做法是让 **WBDrop 进程自己发请求**：临时加一个指向自身直连 IP 的 peer，调 `/api/probe?id=<该 peer>`，返回的 `detail` 才是真实底层错误。`link/mac-netfilter-diag.command` 仍可用于查代理主进程残留，但它不是本问题的判据。

> 换端口**无效**（18500 实测同样 EOF），换 IP 网段也未必有效（绑到 Wi-Fi 地址同样被拦）——这是全局过滤，不是端口或网段策略。

## 端口已通但应用仍「连不上」：一键修复与自测

现场已确认 `arp -a` 学到对端正确 MAC、`Test-NetConnection <对端IP> -Port 18432` 为 `True` 时，**物理链路、IP、路由、两端监听和入站防火墙全部正常**，不要再动网卡和防火墙。剩下只可能是 Windows 端进程 / 浏览器地址 / 配置，按这个顺序：

1. **浏览器地址必须是 `http://127.0.0.1:18432`**。v2 的页面从「对端 IP」打开也能显示（`GET /` 无鉴权），但页面里所有 `/api/*` 都从那个地址发出，源 IP 不是本机 → 一律 401，表现为「页面开得出、一直加载失败／连不上」。**绝不要用 `http://10.20.30.116:18432` 打开 Mac 的页面，也不要用 `http://10.20.30.216:18432` 打开 Windows 自己的页面。**
2. 看设置面板版本号是否为 **2.0.4**；若 `127.0.0.1:18432` 根本打不开，说明 Windows 端不是 v2（仍在跑 v1 单监听器，或换 exe 时旧进程没结束、新进程因端口占用秒退）。结束全部 `wbdrop-windows-amd64.exe` → 覆盖为 `dist/wbdrop-windows-amd64.exe` → 双击并保持控制台窗口。
3. **v2.0.4 起先直接看页面**：状态灯下方与「保存并测试」提示会显示 `detail` 底层错误原文。按原文分层：`EOF` = 连接被中间设备/过滤软件掐断；`i/o timeout` = 对端未放行入站或被静默丢弃；`connection refused` = 对端程序没在监听；`badcode`/401 = 配对码或两端时钟差超过 ±300 秒。
4. 双击 `link/win-fix.bat`，提示输入 Mac 界面显示的配对码时直接回车（默认 `123456`）或填实际值。脚本会：判定版本 → **先做一次不带签名、不带自定义头的裸 `GET /` 对照** → 用保存的码和界面码分别做**带签名的直连请求** → 若保存的码错则通过 `POST /api/config` 自动改正 → 调用本机 `/api/probe` → 发一个 1KB 的 `wbdrop-selftest.txt` 到 Mac。结果写入同目录 `win-fix.txt`。**裸 `GET /` = 200 而带签名请求 = EOF**，说明链路和监听都没问题，被拒的是请求本身（自定义头 / 路径 / 按进程管控），不要再查网络。
5. 自测成功时 Mac 的 `~/Downloads/WBDrop/` 会出现 `wbdrop-selftest.txt`；失败就把 `win-fix.txt` 回传。脚本用 `.NET HttpWebRequest` 发请求并显式禁用代理，绕开被终端管控软件拦截的 `curl.exe`。

> **两个方向是独立的**：Windows 点「保存并测试」是 **Win→Mac（Windows 出站）**；Mac 探测 Windows / 发文件是 **Mac→Win（Windows 入站）**。Windows 防火墙默认不拦出站、但会静默丢弃公网 profile 的未放行入站 SYN，所以完全可能出现「Win→Mac 的 `Test-NetConnection` 为 True，Mac 的 `/api/probe` 却是 `offline`／`i/o timeout`」。换 exe 后按程序路径的允许规则会失效，必须**以管理员重跑 `win-prepare-static.bat`**（输入 `YES`）重建 TCP 18432 入站规则。`win-fix.txt` 会打印当前监听地址和入站规则是否存在。
>
> `auth` 对非本机来源要求 `X-Ts` / `X-Sig` 签名，签名窗为 **±300 秒**；内网机若不能联网对时，两端时钟差超过 5 分钟也会让所有请求返回 401。`win-fix.txt` 会打印两端时钟差。

## 单向连不通：先跑一次分层自检

「Mac 能连 Windows、Windows 连不上 Mac」时，先别改配置。若 Mac 侧 `lsof -nP -iTCP:18432 -sTCP:LISTEN` 已同时有 `127.0.0.1:18432` 和直连 IP 的监听、两端同网段、Mac 的 `/api/probe` 返回 `ok`，那么剩下的阻塞点只有三个：**macOS 应用防火墙拦入站**、**Windows 侧出站被管控软件拦**、**Windows 保存的对端 IP / 配对码填错**。按顺序：

1. Windows 双击 `link/win-diag.bat`（只读，不需要管理员），生成同目录 `win-diag.txt`。**必须在原生 PowerShell / cmd 里跑，不要在 WSL 或代理 shell 里跑**——WSL 的 `172.21.48.1/20` 是另一个网卡，测不了直连线。
2. 看报告第 3 节 `TCP layer`：
   - `CLOSED / TIMEOUT` → 在 Mac 跑 `./link/mac-firewall-allow.command`（需 sudo），**然后关掉并重新双击 Mac 端 WBDrop**（防火墙在进程启动时打标记，不重启不生效），再回 Windows 点「保存并测试」。仍不行就用 `OFF=1 ./link/mac-firewall-allow.command` 临时关掉 macOS 应用防火墙做判定，测完用 `ON=1` 恢复。
   - `OPEN` 但第 5 节 probe 不是 `ok` → 看第 1 节的 `[WARN]`：对端 IP 必须是 Mac 的直连 IP，对端配对码必须填**Mac 界面上显示的那个码**，不是 Windows 自己的。
3. 把 `win-diag.txt` 回传，再按具体结果收尾。

> **报告里 `127.0.0.1:18432 CLOSED` 但 `10.20.30.216:18432` 有响应**：说明 Windows 端跑的是**旧版 v1 单监听器**（v2 源码 `main.go` 必然同时监听 `127.0.0.1`）。v1 的页面从 `http://10.20.30.216:18432` 打开，浏览器跨源直连对端 IP，会遇到 CORS / 非安全上下文 / 系统代理，表现为「Mac 能连 Win、Win 连不上 Mac」。**换成 `dist/wbdrop-windows-amd64.exe` v2.0.5 并重启，页面改从 `http://127.0.0.1:18432` 打开**即可。诊断脚本会自动识别这种情况并写进 `VERDICT`。
>
> 报告第 4 节对 Mac 的 `/api/info` 裸请求**预期是 401**（接口有鉴权包装），`200`/`401` 都代表 Mac 服务活着；`000` 多半是 Windows 上 `curl.exe` 被终端管控软件拦，可用报告里的 `.NET HttpWebRequest` 那行交叉判断，不要据此认为链路断了。

| 现象 | 原因 | 处理 |
|---|---|---|
| **Mac 本机 `127.0.0.1:18432` 正常但直连 IP 返回 `HTTP 000`；换端口、重建监听都无效；`Mac→Win` 却完全正常** | 若这个 `000` 来自受限终端 / AI 代理的 shell，是**假阳性**（同一 shell 连 Windows 也是 `000`）；真实场景最常见的是 **macOS 应用防火墙对未签名 WBDrop 关闭入站连接**（见上一节）。Network Extension（AdGuard / Proxifier）全退后现象不变，已排除 | 用 WBDrop **进程内** `/api/probe` 自连取真实 `detail`；`codesign -dvv <运行中二进制>` 显示 `not signed at all` 就换 **v2.0.5 已签名 macOS 二进制并重启**。退出代理软件、换端口、重建监听器都无效 |
| **两端都是 v2、配对码正确、Mac→Win 探测 `ok`，但 Win→Mac 的 `/api/probe` 是 `offline`，直连请求报 `The underlying connection was closed`** | `EOF`（零响应字节）+ TCP 握手成功 + Mac→Win 正常 + `codesign` 显示未签名 = **macOS 应用防火墙按代码签名标识拦截入站**（见上一节）。配对码错只会返回 401，不会关闭连接；网络扩展、端口、双监听器结构均已实测排除 | 换 `dist/wbdrop-macos-amd64` **v2.0.5**（`build.sh` 已自动 ad-hoc 签名）并**重启 Mac 端程序**；`codesign -dvv <二进制>` 应显示 `Signature=adhoc`。换端口、重加防火墙白名单、重建监听器都不解决。需要证据时用 `win-fix.bat` 的深挖分支打印裸 TCP 原始字节 |
| Mac 的 `/api/probe` 时好时坏，甚至 `dial tcp ... i/o timeout`，但 Windows 上 `Test-NetConnection <MacIP> -Port 18432` 一直 True | 方向不同：前者是 **Mac→Win（Windows 入站）**，后者是 **Win→Mac（Windows 出站）**。公网 profile 下缺入站规则时 SYN 被静默丢弃；换 exe 会让按程序路径的允许规则失效 | 以管理员运行 `win-prepare-static.bat` 并输入 `YES` 重建 TCP 18432 入站规则；保持 WBDrop 控制台窗口开着；再从 Mac 侧复测 `/api/probe` |
| **TCP 18432 已 OPEN、ARP/路由全对，但页面仍显示连不上 / 加载失败** | 浏览器打开的是**对方或本机直连 IP** 而不是 `127.0.0.1:18432`；或 Windows 端仍跑 v1 单监听器；或保存的配对码不是 Mac 界面显示的那个 | 先把地址栏改成 `http://127.0.0.1:18432` 并强制刷新；再双击 `link/win-fix.bat`（自动判版本、自动改配对码、发 1KB 自测文件），把 `win-fix.txt` 回传 |
| **Windows 能 ping 通 Mac 的直连 IP，但 `IP:18432` 连不上** | Mac 的 USB 网卡掉线（`ifconfig en6` = `status: inactive`、无 `inet`），`10.20.30.116` 已不在 Mac 上，WBDrop 自然没在该地址监听；若此时重启过 WBDrop，v2.0.2 还会把保存的 `bind` 清空落盘。ping 通多半是 Windows 的 ARP 缓存或另一台设备，用 `arp -a` 核对 MAC 是否为 `02-00-00-00-00-01` | 重新插拔 USB 网卡与网线，等「系统设置 → 网络 → USB 10/100 LAN」变绿；然后**双击 `link/mac-link-recover.command`**（不用重启、不用换 exe）一次性把运行实例的 `bind` 写回并验证双监听。长期用 **v2.0.3**：以后插线 3 秒内自动恢复 |
| Windows 端 `win-diag.txt` 显示 `127.0.0.1:18432 CLOSED`、但 Mac 仍能探测到 Windows | Windows 跑的是**旧版 v1 单监听器**，只绑直连 IP；v1 的浏览器跨源直连对端会失败 | 结束旧进程，换 `dist/wbdrop-windows-amd64.exe` **v2.0.3** 重启，页面改从 `http://127.0.0.1:18432` 打开；再以管理员跑 `win-prepare-static.bat` 重建防火墙规则 |
| Windows 防火墙规则显示 MISSING，且刚换过 exe | 旧规则按程序路径或旧名称建，换文件后失效；`profile=public` 未覆盖 | 以管理员运行 `win-prepare-static.bat`（按提示输入 `YES`），它会自动加 `TCP 18432` 入站规则并把运行实例绑到 `10.20.30.216` |
| 点「保存并测试」没反应 / 页面显示「加载失败」/ 浏览器控制台 `Cannot read properties of null (reading 'push')` | v2.0.0 把空对端列表返回成 `null`，前端崩溃 | **两端都换成 v2.0.1 的可执行文件**，关掉旧进程后重新双击。旧配置里的 `peers: null` 会在启动时自动规范成 `[]`，无需手工删文件 |
| 「已保存，但暂时连不上对方」，且电脑配置了公司代理 | v2.0.0 的对端请求走了 `HTTP_PROXY`，被代理拦截返回 403 | 换 v2.0.1：所有对端请求强制 `Proxy: nil`，只直连配置里的字面 IP |
| **一台显示「已连接」，另一台却「暂时连不上」** | 显示「已连接」的那台**没有在直连网卡上监听**：它只绑了 `127.0.0.1`，主动连出去没问题（出站不受监听影响），但收不到对方发起的连接。常见于 `mac-eth-back-dhcp.command` 跑完后 `bind` 被留空、或换版本重启后没重新选网卡 | 在该机「设置 → 直连网卡」选中插着对端网线的网卡并保存，两端状态灯都应变绿；v2.0.2 起会直接显示「单向 · 对方连不上你」并给出常驻黄色提示 |
| 该机监听地址正确、两端同网段、Mac→Win 探测 `ok`，但 Win→Mac 仍连不上 | macOS 应用防火墙按**代码签名标识**放行：未签名的 Go 二进制每次重建都成为新程序，旧规则失效，入站连接被 accept 后直接关闭（TCP 通、HTTP 零字节 EOF）；`--getappblocked` 仍可能误报 permitted | 换 **v2.0.5** 的 macOS 二进制（`build.sh` 自动 ad-hoc 签名）并重启。`link/mac-firewall-allow.command` 仅对旧版未签名程序有缓解作用，且每换一次 exe 都要重加；`OFF=1` 临时关防火墙可用于判定，但不是长期方案 |
| `win-start-link.bat` 报 `hosted network NOT SUPPORTED` | 无线网卡驱动不支持承载网络（Intel CNVi 网卡常见） | 改用方式 B（网线直连）或蓝牙 |
| Mac 连上 `WBDrop-Link` 后没有 `169.254.x.x` 地址 | Windows 侧 169.254 静态地址被系统拒绝，已回退到 192.168.137.1 | 按脚本末尾提示，在 Mac 执行 `sudo networksetup -setmanual Wi-Fi 192.168.137.2 255.255.255.0 192.168.137.1` |
| Mac 连上后上不了网 | 正常现象，唯一的无线接口被链路占用 | 传完运行 `mac-link-down.command` |
| 软 AP 启动失败 | Wi-Fi 开关关闭，或无线网卡正连着别的网络 | 打开 Wi-Fi，断开已连接的网络后重试 |
| 状态灯一直显示「未选择直连网卡」 | 网卡是静态 IP，或网线没插好 | 「设置 → 直连网卡」选中插着直连线的网卡，点「保存」 |
| 状态灯显示「未连接」 | 两端不在同一网段（静态 IP 场景的典型症状），或对端程序没启动 | 按 [SETUP.md](SETUP.md)「链路配置」一节跑两个一键脚本；内网机 `ipconfig`、Mac `ifconfig` 比对网段 |
| Mac `ifconfig en6` 显示 `netmask 0xffffffff` | 在系统设置里误选了「使用 DHCP（手动地址）」，macOS 给了 `/32` 掩码，**没有到对端的路由** | 跑 `./mac-eth-join-static.command <Windows的IP> <掩码>`，脚本会用 `-setmanual` 改成正确掩码；或手工在 TCP/IP 里选「手动」并填掩码 |
| Mac 配完静态地址后 `ping <对端IP>` 无响应 | Windows 防火墙常拦 ICMP，或掩码仍是 `/32` | 先确认掩码：`ifconfig en6 \| grep netmask` 应为 `0xffffff00`（/24）而非 `0xffffffff`；再在 WBDrop 里点「保存并测试」判断真实连通性 |
| 脚本提示 `WARNING: SUBNET OVERLAP` | 内网机网段与 Mac Wi-Fi 网段重叠 | 传输时临时关闭 Mac Wi-Fi，或请 IT 换一个不重叠的直连网段；重叠时强行继续会导致路由错乱 |
| 拖入文件没反应，只弹出黄色提示 | 还没有保存任何对端 | 点「设置」，填一次别名 + IP + 对方配对码，点「保存并测试」 |
| `mac-eth-join-static.command` 报 `no USB ethernet adapter found` | 适配器未插好，或服务名不在识别列表内 | 重新插好适配器再跑；或按脚本提示在「系统设置 → 网络」手动配 IP |
| Mac 配了静态地址后打不开网页 | USB 网卡在服务顺序里排在 Wi-Fi 之前 | 系统设置 → 网络 → 右下角「⋯」→ 设定服务顺序，把 Wi-Fi 拖到 USB 网卡之上 |
| 传完忘了把 Mac 改回自动获取 | — | 运行 `./mac-eth-back-dhcp.command` |
| 状态灯「未连接」，但两端地址看着没问题 | Windows 防火墙未放行 | 执行 [SETUP.md](SETUP.md) 里的 `netsh` 命令 |
| 状态灯「配对码错误」 | 填的是本机配对码，或抄错了 | 在「已保存的对端」点「编辑」，改填**对方界面上**显示的配对码。v2 配对码固定不变，重启不会换 |
| 换个 Windows 用户运行后配置丢了 | 配置按用户主目录隔离 | 把 `C:\Users\<旧用户名>\.wbdrop\config.json` 拷到新用户同名目录，或重新添加一次 |
| 传输到一半中断 | 网线松动，或对端程序被关闭 | 点该条目上的「重试」。重名文件会自动加 `-1` 后缀，不会覆盖 |
| 双击 exe 后窗口一闪而过 | 端口被占用或目录无权限 | 程序会暂停显示错误原因；若仍看不到，在命令提示符里运行以查看输出 |
| 接收目录找不到文件 | 重名文件自动加了 `-1`、`-2` 后缀 | 查看目录，同名文件不会被覆盖 |
