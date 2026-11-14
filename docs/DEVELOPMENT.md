# 开发与构建

单文件 Go 程序，仅依赖标准库；前端用 `//go:embed` 打包进二进制。

---

需要 Go 1.18 或更高版本。macOS 上一条命令产出全部平台：

```bash
./build.sh
```

等价于：

```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o dist/wbdrop-windows-amd64.exe .
GOOS=darwin  GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o dist/wbdrop-macos-amd64 .
GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o dist/wbdrop-macos-arm64 .
```

`CGO_ENABLED=0` 保证纯静态链接，产物无任何运行时依赖。这也正是选择 Go 的原因——**Python 的 PyInstaller 无法交叉编译**，必须在 Windows 上构建，而内网机装不了 Python 环境。

运行测试：

```bash
go test ./...
```

覆盖签名校验、路径穿越防护、鉴权分支、配置校验与非法地址拒绝、端到端上传与完整性校验、大小不符时的清理，以及 v2 的**发送代理全链路**（浏览器 → `/api/send` → 签名转发 → 对端落盘）。

## 代码结构

```
wbdrop/
├── main.go            服务端：配置持久化、双监听器、发送代理、流式接收、鉴权（约 1200 行）
├── main_test.go       测试：签名、净化、鉴权、配置校验、发送代理端到端（约 360 行）
├── ui/index.html      前端：单页，内嵌进二进制（约 470 行）
├── link/
│   ├── win-start-link.bat     Windows 建软 AP（提权后调用 ps1）
│   ├── win-start-link.ps1     检测驱动能力、创建 hosted network、配 IP、放行防火墙
│   ├── win-stop-link.bat      关闭软 AP 与防火墙规则
│   ├── mac-link-up.command    连上软 AP，记住原网络
│   ├── mac-link-down.command  切回原网络
│   ├── win-prepare-static.bat     Windows 静态 IP 场景：管理员提权入口
│   ├── win-prepare-static.ps1     显示真实 IP/掩码、放行防火墙、自动绑定 WBDrop
│   ├── mac-eth-join-static.command  参数为「Windows 的 IP + 掩码」；自动选地址、修 /32、查网段重叠、自动绑定
│   ├── mac-eth-back-dhcp.command   恢复 DHCP 并自动重新绑定
│   ├── win-diag.bat / .ps1         Windows 分层自检（只读，输出 win-diag.txt）
│   ├── win-fix.bat / .ps1          Windows 一键修复+自测：判版本、验/改配对码、probe、发 1KB 测试文件（输出 win-fix.txt）
│   ├── mac-netfilter-diag.command  Mac 侧只读诊断：代理主进程残留 / 网络扩展状态（不能判定签名问题）
│   ├── mac-firewall-allow.command  旧版未签名程序的入站放行缓解；OFF=1 / ON=1 可临时开关做判定
│   └── mac-link-recover.command    网卡掉线后一键恢复运行实例的 bind（不改网络设置、不重启）
├── go.mod             仅声明 module，无第三方依赖
├── build.sh           三平台交叉编译；v2.0.5 起构建后自动对 macOS 产物做 ad-hoc 签名
├── docs/              建链、使用、排查、安全、开发文档
├── LICENSE            MIT
├── .gitignore         忽略 dist/ 与脚本运行时生成的 win-fix.txt / win-diag.txt
└── dist/              编译产物（两个 macOS 二进制均带 adhoc 签名；不入版本库）
```

`main.go` 有两处监听：`127.0.0.1:18432` 常驻（本机 UI），另一处是可切换的直连监听器，由 `POST /api/config` 中的 `bind` 字段更换。切换只关旧监听器、建新监听器，进程不重启，本机 UI 也不会失联。

**v2 的数据流**：浏览器把文件 `POST` 到本机的 `/api/send`，后端用 `config.json` 里保存的配对码算出签名，先向对端声明会话，再把上传流原样转发给对端的 `/api/recv/blob/`。浏览器从头到尾只与 `127.0.0.1` 通信，因此不存在跨源限制，也不依赖浏览器的加密接口。配对码不出现在页面 JS 里。

前端通过 `//go:embed` 打包进可执行文件，因此分发时只需要一个文件。

---

## 发布一个版本

`dist/` 不进版本库，二进制通过 GitHub Releases 分发。发版流程：

**1. 同步版本号（两处，必须一致）**

```bash
main.go:44     appVersion = "2.0.5"
build.sh:9     VERSION="2.0.5"
```

**2. 构建并自测**

```bash
./build.sh          # 三个产物落到 dist/，macOS 两个自动 ad-hoc 签名
go test ./...       # 全绿再发
```

**3. 验证签名（macOS 侧「连不上」问题只在这里能提前发现）**

```bash
codesign -dvv dist/wbdrop-macos-arm64 2>&1 | grep -E 'Signature=|Identifier='
# 必须出现 Signature=adhoc；出现 "not signed at all" 就别发
```

**4. 打 tag 并推送**

```bash
git tag -a v2.0.5 -m "v2.0.5"
git push origin main --tags
```

**5. 建 Release 并上传产物**

GitHub → Releases → **Draft a new release** → 选 `v2.0.5` → 标题 `v2.0.5` → 上传 `dist/` 下三个文件：

```
wbdrop-windows-amd64.exe
wbdrop-macos-amd64
wbdrop-macos-arm64
```

说明里写清本次修的是什么、以及下面这条给 macOS 用户的提示。

**6. 提醒 macOS 用户补权限**

浏览器下载的可执行文件没有执行位，首次运行前需要：

```bash
chmod +x wbdrop-macos-arm64
xattr -d com.apple.quarantine wbdrop-macos-arm64   # 绕过 Gatekeeper 隔离
```

> 没有 `gh` CLI 也能发版，网页操作即可。装了 `gh` 的话等价于：
>
> ```bash
> gh release create v2.0.5 dist/wbdrop-* --title v2.0.5 --notes "…"
> ```

### 发版检查清单

- [ ] `main.go` 与 `build.sh` 的版本号一致
- [ ] `go test ./...` 通过
- [ ] `codesign -dvv` 显示 `Signature=adhoc`
- [ ] Release 三个产物齐全，文件名与 README 表格一致
- [ ] README 里 `docs/TROUBLESHOOTING.md` 提到的最低版本号已同步
