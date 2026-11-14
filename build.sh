#!/bin/bash
# 交叉编译脚本 —— 在 macOS 上一次产出全部目标平台的可执行文件
# 产物为纯静态单文件, 无运行时依赖, 拷贝到目标机双击即可运行。
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p dist

VERSION="2.0.5"   # 与 main.go 的 appVersion 保持一致
LDFLAGS="-s -w"
echo "WBDrop v$VERSION"

build() {
  local goos=$1 goarch=$2 out=$3
  echo "building $goos/$goarch -> dist/$out"
  GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 \
    go build -trimpath -ldflags="$LDFLAGS" -o "dist/$out" .
}

build windows amd64 wbdrop-windows-amd64.exe
build darwin  amd64 wbdrop-macos-amd64
build darwin  arm64 wbdrop-macos-arm64

# macOS 应用防火墙 (socketfilterfw) 按「代码签名标识」管理「允许传入连接」。
# 未签名的 Go 二进制每次重建都被内核视为全新程序, 旧放行规则随之失效:
# 对端 TCP 握手能成功, 但 HTTP 请求会被立刻关闭 (curl 52 / Go EOF),
# 且 --getappblocked 仍显示 permitted, 极具迷惑性。
# ad-hoc 签名让标识稳定, 是直连网卡能被对端访问的前提。
if [ "$(uname -s)" = "Darwin" ] && command -v codesign >/dev/null 2>&1; then
  for f in dist/wbdrop-macos-amd64 dist/wbdrop-macos-arm64; do
    if ! codesign -s - --force "$f" >/dev/null 2>&1; then
      echo "ERROR: codesign failed for $f - refusing to ship an unsigned macOS binary" >&2
      exit 1
    fi
    echo "signed (adhoc) $f"
  done
else
  echo "WARN: codesign unavailable on this host; macOS binaries stay UNSIGNED and" >&2
  echo "      inbound connections will be blocked by the macOS Application Firewall." >&2
fi

chmod +x dist/wbdrop-macos-amd64 dist/wbdrop-macos-arm64 2>/dev/null || true

echo ""
echo "done. artifacts in dist/:"
ls -lh dist/
