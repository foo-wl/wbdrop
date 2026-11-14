// WBDrop - 双机点对点文件传输
//
// 设计原则:
//  1. 只绑定用户显式选定的那块直连网卡地址, 绝不监听 0.0.0.0,
//     确保服务不会暴露在内网网卡或公网网卡上。
//  2. 纯标准库, 无外部依赖, CGO_ENABLED=0 静态链接,
//     可在 macOS 上交叉编译出 Windows 单文件可执行程序。
//  3. 对端配置持久化在本机 ~/.wbdrop/config.json, 一次填写长期生效。
//  4. 浏览器只与本机 127.0.0.1 通信, 由后端用保存的配对码签名并向对端转发,
//     因此不存在跨源(CORS)问题, 也不要求页面处于安全上下文。
//  5. 裸 body 流式转发/写盘, 常数内存, 不落临时文件。
//  6. 对端访问必须携带 HMAC-SHA256 签名 (配对码派生), 本机访问免签。
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed ui/index.html
var uiFS embed.FS

const (
	appVersion  = "2.0.5"
	defaultPort = 18432
	maxFileSize = int64(2) << 30 // 单文件上限 2 GiB
	maxFiles    = 500            // 单批次文件数上限
	maxPeers    = 20             // 保存的对端数量上限
	signWindow  = 300            // 签名时间窗 ±300s
	linkLocal   = "169.254."
)

// ---------------------------------------------------------------- 类型定义

// Peer 是一个保存下来的对端。配对码属于"对方那台机器", 用于给发往对方的请求签名。
type Peer struct {
	ID    string `json:"id"`
	Alias string `json:"alias"`
	IP    string `json:"ip"`
	Port  int    `json:"port"`
	Code  string `json:"code"`
}

// Config 是会持久化的全部用户设置。Code 是本机的配对码, 生成后保持不变。
type Config struct {
	Code   string `json:"code"`
	Bind   string `json:"bind"`
	Active string `json:"active"`
	Peers  []Peer `json:"peers"`
}

// FileMeta 是客户端声明的文件元信息。
type FileMeta struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// Upload 表示一次接收会话。
type Upload struct {
	ID      string
	Files   []FileMeta
	Written []int64
	Total   int64
	Done    bool
	Err     string
	Started time.Time
	From    string
	mu      sync.Mutex
}

// HistEntry 是已完成会话的摘要。
type HistEntry struct {
	Name string    `json:"name"`
	Size int64     `json:"size"`
	At   time.Time `json:"at"`
	From string    `json:"from"`
}

var (
	storeMu sync.RWMutex
	uploads = map[string]*Upload{}

	histMu sync.Mutex
	hist   []HistEntry

	cfgPort int
	cfgDir  string
	cfgBind string
	cfgCode string
	cfgName string

	// 网卡地址表会随插拔网线变化, 因此用读写锁保护, 并周期性刷新。
	addrMu   sync.RWMutex
	localIPs map[string]bool
	allIPv4  []IPv4Addr

	// 配置与配对码可在运行时被修改, 读写都加锁。
	cfgMu   sync.RWMutex
	curCfg  Config
	cfgPath string // 为空时不落盘(仅测试环境)

	codeMu sync.RWMutex
)

func currentCode() string {
	codeMu.RLock()
	defer codeMu.RUnlock()
	return cfgCode
}

func setCode(s string) {
	codeMu.Lock()
	cfgCode = s
	codeMu.Unlock()
}

func snapConfig() Config {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	c := curCfg
	// 必须保留"非 nil 的空 slice": append([]Peer(nil), empty...) 会返回 nil,
	// 序列化成 "peers": null, 前端 state.cfg.peers.push 会直接抛 TypeError。
	// 用 make+copy 保证 JSON 始终是 [] 而不是 null。
	c.Peers = make([]Peer, len(curCfg.Peers))
	copy(c.Peers, curCfg.Peers)
	return c
}

func findPeer(id string) (Peer, bool) {
	if id == "" {
		id = snapConfig().Active
	}
	if id == "" {
		return Peer{}, false
	}
	for _, p := range snapConfig().Peers {
		if p.ID == id || p.Alias == id {
			return p, true
		}
	}
	return Peer{}, false
}

// ---------------------------------------------------------------- 配置持久化

func configFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".wbdrop", "config.json")
	}
	return filepath.Join(home, ".wbdrop", "config.json")
}

// writeConfig 直接覆盖写。配置很小且只有一个进程写, 用 rename 在 Windows 上
// 会因目标已存在而失败, 因此不引入原子替换。
func writeConfig(c Config) error {
	if cfgPath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(cfgPath, b, 0o600)
}

func loadConfig() Config {
	b, err := os.ReadFile(cfgPath)
	c := Config{Peers: []Peer{}}
	if err == nil {
		_ = json.Unmarshal(b, &c)
	}
	if c.Code == "" {
		c.Code = randomCode() // 只在首次生成一次, 之后固定不变
	}
	if c.Peers == nil {
		c.Peers = []Peer{}
	}
	_ = writeConfig(c)
	return c
}

// validateConfig 规范化并校验前端提交的全量配置。
func validateConfig(c *Config) error {
	c.Code = strings.TrimSpace(c.Code)
	if c.Code == "" || len([]rune(c.Code)) > 32 {
		return fmt.Errorf("本机配对码不能为空且不超过 32 字符")
	}
	c.Bind = strings.TrimSpace(c.Bind)
	if len(c.Peers) > maxPeers {
		return fmt.Errorf("最多保存 %d 个对端", maxPeers)
	}
	seen := map[string]bool{}
	for i := range c.Peers {
		p := &c.Peers[i]
		p.ID = strings.TrimSpace(p.ID)
		if p.ID == "" {
			p.ID = randomID()
		}
		if seen[p.ID] {
			return fmt.Errorf("对端 ID 重复: %s", p.ID)
		}
		seen[p.ID] = true
		p.Alias = strings.TrimSpace(p.Alias)
		p.IP = strings.TrimSpace(p.IP)
		p.Code = strings.TrimSpace(p.Code)
		if p.Alias == "" || len([]rune(p.Alias)) > 40 {
			return fmt.Errorf("别名不能为空且不超过 40 字符")
		}
		// 只接受字面 IP: 不允许主机名, 避免任何 DNS 解析与意外外联。
		ip := net.ParseIP(p.IP)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("对端地址必须是 IPv4 字面量: %q", p.IP)
		}
		if p.Port == 0 {
			p.Port = defaultPort
		}
		if p.Port < 1 || p.Port > 65535 {
			return fmt.Errorf("端口超出范围: %d", p.Port)
		}
		if p.Code == "" {
			return fmt.Errorf("请填写 %s 的配对码", p.Alias)
		}
	}
	if c.Active != "" && !seen[c.Active] {
		c.Active = ""
	}
	if c.Active == "" && len(c.Peers) > 0 {
		c.Active = c.Peers[0].ID
	}
	// 前端可能提交 "peers": null (旧配置或第三方调用), 统一规范成空数组,
	// 否则写回磁盘并在响应里返回 null, 前端会再次崩溃。
	if c.Peers == nil {
		c.Peers = []Peer{}
	}
	return nil
}

// ---------------------------------------------------------------- 监听器管理

// 服务始终在回环地址上监听(本机 UI 使用), 另有一个可切换的"直连"监听器,
// 只绑定用户选中的那一块网卡的地址, 绝不监听 0.0.0.0。
var (
	lanMu sync.Mutex
	lanLn net.Listener
	lanIP string
	srv   *http.Server
)

func currentLAN() string {
	lanMu.Lock()
	defer lanMu.Unlock()
	return lanIP
}

// setLANListener 把直连监听器切换到指定地址; 传空串表示关闭直连监听。
func setLANListener(ip string) error {
	lanMu.Lock()
	defer lanMu.Unlock()
	if lanLn != nil {
		lanLn.Close()
		lanLn = nil
	}
	lanIP = ""
	if ip == "" || ip == "127.0.0.1" {
		return nil
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(ip, strconv.Itoa(cfgPort)))
	if err != nil {
		return err
	}
	lanLn = ln
	lanIP = ip
	go func(l net.Listener) {
		// 切换地址时旧监听器会被主动关闭, Serve 返回错误属正常现象。
		_ = srv.Serve(l)
	}(ln)
	return nil
}

// tryRestoreLAN 在直连网卡重新上线后自动恢复监听。
// 只恢复「用户或脚本显式保存过」的地址: 不猜测、不自动采纳办公网地址、
// 绝不监听 0.0.0.0。典型场景是 Mac 睡眠 / USB 网卡掉电后重新插线 ——
// macOS 会把静态地址还给 en6, 这里随即把监听器挂回去, 无需手工点选。
func tryRestoreLAN() {
	cfgMu.RLock()
	want := curCfg.Bind
	cfgMu.RUnlock()
	if restoreTarget(want, currentLAN(), isLocalIP(want)) == "" {
		return
	}
	lanMu.Lock()
	busy := lanIP != ""
	lanMu.Unlock()
	if busy {
		return
	}
	if err := setLANListener(want); err != nil {
		return
	}
	log.Printf("直连网卡已恢复, 自动重新监听 %s:%d", want, cfgPort)
}

// restoreTarget 返回应该自动恢复监听的地址; 空串表示什么都不做。
// 只认显式保存过、且此刻确实属于本机的地址, 不覆盖已有监听、不猜测新地址。
func restoreTarget(saved, current string, local bool) string {
	if saved == "" || saved == "127.0.0.1" || current != "" || !local {
		return ""
	}
	return saved
}

// ---------------------------------------------------------------- 入口

func main() {
	flag.IntVar(&cfgPort, "port", defaultPort, "监听端口")
	flag.StringVar(&cfgDir, "dir", defaultDir(), "接收目录")
	flag.StringVar(&cfgBind, "bind", "", "绑定地址, 默认自动选择 169.254 链路本地地址")
	flag.StringVar(&cfgCode, "code", "", "配对码, 默认随机生成 6 位数字")
	noBrowser := flag.Bool("no-browser", false, "启动后不自动打开浏览器")
	flag.Parse()

	cfgName, _ = os.Hostname()
	refreshAddrs()

	// 配置优先从磁盘恢复: 配对码固定、直连网卡自动沿用上次选择。
	cfgPath = configFilePath()
	c := loadConfig()
	if cfgCode == "" { // 命令行 -code 显式指定时以命令行为准
		setCode(c.Code)
	}
	c.Code = currentCode()
	cfgMu.Lock()
	curCfg = c
	cfgMu.Unlock()
	_ = writeConfig(c)

	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		die("无法创建接收目录 %s: %v", cfgDir, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/api/info", auth(handleInfo))
	mux.HandleFunc("/api/config", auth(handleConfig))
	mux.HandleFunc("/api/probe", auth(handleProbe))
	mux.HandleFunc("/api/send", auth(handleSend))
	mux.HandleFunc("/api/recv/init", auth(handleInit))
	mux.HandleFunc("/api/recv/blob/", auth(handleBlob))
	mux.HandleFunc("/api/recv/status/", auth(handleStatus))

	srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// 回环监听器常驻: 本机 UI 始终可通过 http://localhost 打开,
	// 这样即使直连地址切换成 10.x, UI 也不会失联。
	loopAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(cfgPort))
	loopLn, err := net.Listen("tcp", loopAddr)
	if err != nil {
		die("无法监听 %s: %v\n  端口可能已被占用, 换一个: -port 18500", loopAddr, err)
	}

	// 直连地址优先级: 命令行 > 上次保存 > 自动采纳的 169.254 链路本地地址。
	// 常规网段地址(内网静态 IP / Wi-Fi)绝不自动采用, 避免误绑到办公网络。
	//
	// 网卡临时离线(拔线 / USB 网卡休眠 / 睡眠唤醒)时, 保存的地址会暂时不
	// 属于本机。此时绝不能把空地址写回配置 —— 否则仅仅一次重启就永久丢掉
	// 绑定, 插线回来还得手工重选。保留原值, 由 tryRestoreLAN 在地址重新
	// 出现时自动恢复监听。
	auto := ""
	if c.Bind == "" {
		auto = pickBindAddr()
	}
	lan, persist, offline := startupBindDecision(cfgBind, c.Bind, auto, isLocalIP)
	if offline {
		fmt.Println("  NOTE: 直连网卡当前离线 (" + c.Bind + "), 暂时只在 127.0.0.1 监听; 插线后会自动恢复。")
	}
	if lan != "" && !isLocalIP(lan) {
		die("指定的地址 %s 不属于本机任何网卡。\n  可用地址:\n%s", lan, indentAddrs(addrList()))
	}
	if err := setLANListener(lan); err != nil {
		die("无法监听 %s: %v\n  端口可能已被占用, 换一个: -port 18500", lan, err)
	}
	// 只有确实选中了地址才回写; 网卡离线时保留上次保存的地址。
	cfgMu.Lock()
	if persist {
		curCfg.Bind = lan
	}
	c = curCfg
	cfgMu.Unlock()
	_ = writeConfig(c)

	printBanner(currentLAN(), loopAddr)
	printWarnings()

	// 网线插拔会改变地址表, 定时刷新, 让 UI 与鉴权判断跟上;
	// 顺便在直连网卡恢复上线时把监听器自动挂回去。
	go func() {
		for range time.Tick(3 * time.Second) {
			refreshAddrs()
			tryRestoreLAN()
		}
	}()

	if !*noBrowser {
		go func() {
			time.Sleep(300 * time.Millisecond)
			openBrowser("http://localhost:" + strconv.Itoa(cfgPort))
		}()
	}

	if err := srv.Serve(loopLn); err != nil && err != http.ErrServerClosed {
		die("服务异常退出: %v", err)
	}
}

// startupBindDecision 决定启动时监听哪个直连地址, 以及是否回写配置。
// saved 是配置里上次保存的地址, auto 是自动采纳的 169.254 链路本地地址。
// offline=true 表示网卡临时离线: 本次不建直连监听, 且绝不把空地址写回
// 配置 —— 否则拔线期间的一次重启就会永久丢掉绑定。
func startupBindDecision(cli, saved, auto string, local func(string) bool) (lan string, persist, offline bool) {
	if cli != "" {
		return cli, true, false
	}
	if saved != "" {
		if local(saved) {
			return saved, true, false
		}
		return "", false, true
	}
	if auto != "" {
		return auto, true, false
	}
	return "", true, false
}

// ---------------------------------------------------------------- 启动辅助

func defaultDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "WBDrop"
	}
	dl := filepath.Join(home, "Downloads")
	if st, err := os.Stat(dl); err == nil && st.IsDir() {
		return filepath.Join(dl, "WBDrop")
	}
	return filepath.Join(home, "WBDrop")
}

// IPv4Addr 记录一个本机 IPv4 地址及其所属网卡, 用于 UI 上区分"哪根线"。
type IPv4Addr struct {
	IP    string `json:"ip"`
	Iface string `json:"iface"`
}

// scanAddrs 返回 (本机所有 IPv4 集合, 非回环 IPv4 列表)。
func scanAddrs() (map[string]bool, []IPv4Addr) {
	set := map[string]bool{"127.0.0.1": true, "::1": true}
	var list []IPv4Addr
	ifaces, err := net.Interfaces()
	if err != nil {
		return set, list
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() {
				continue
			}
			s := ip4.String()
			set[s] = true
			list = append(list, IPv4Addr{IP: s, Iface: ifc.Name})
		}
	}
	return set, list
}

// refreshAddrs 重新扫描网卡地址表。插拔网线后必须调用, 否则地址与鉴权判断会过期。
func refreshAddrs() {
	set, list := scanAddrs()
	addrMu.Lock()
	localIPs, allIPv4 = set, list
	addrMu.Unlock()
}

// isLocalIP 判断某个地址是否属于本机(含回环)。
func isLocalIP(ip string) bool {
	addrMu.RLock()
	defer addrMu.RUnlock()
	return localIPs[ip]
}

// addrList 返回当前非回环 IPv4 列表的副本。
func addrList() []IPv4Addr {
	addrMu.RLock()
	defer addrMu.RUnlock()
	out := make([]IPv4Addr, len(allIPv4))
	copy(out, allIPv4)
	return out
}

// indentAddrs 把地址列表格式化成带缩进的多行文本, 用于控制台提示。
func indentAddrs(list []IPv4Addr) string {
	if len(list) == 0 {
		return "    (无可用地址, 请确认网线已插好)"
	}
	var b strings.Builder
	for _, a := range list {
		fmt.Fprintf(&b, "    %-16s [%s]\n", a.IP, a.Iface)
	}
	return strings.TrimRight(b.String(), "\n")
}

// pickBindAddr 只自动采纳 169.254.x.x 链路本地地址。
// 这类地址仅在网卡拿不到 DHCP 时自动生成, 是"直连但未接入任何网络"的可靠信号。
// 其他地址(内网静态 IP、Wi-Fi 地址)一律不自动采用, 必须由用户显式选择,
// 避免服务被绑到内网或办公网络上。
func pickBindAddr() string {
	for _, a := range addrList() {
		if strings.HasPrefix(a.IP, linkLocal) {
			return a.IP
		}
	}
	return ""
}

// die 打印错误后退出。Windows 双击运行时控制台窗口会随进程结束而关闭,
// 因此暂停等待回车, 避免用户只看到窗口一闪而过。
func die(format string, args ...interface{}) {
	fmt.Println("\n  ERROR: " + fmt.Sprintf(format, args...))
	if runtime.GOOS == "windows" {
		fmt.Print("\n  按回车键退出...")
		fmt.Scanln()
	}
	os.Exit(1)
}

func printBanner(bind, loopAddr string) {
	fmt.Println("")
	fmt.Println("  WBDrop " + appVersion + " - point-to-point file transfer")
	fmt.Println("  --------------------------------------------------")
	fmt.Printf("  machine   : %s\n", cfgName)
	fmt.Printf("  local ui  : %s\n", loopAddr)
	if bind == "" {
		fmt.Printf("  direct ip : (未选择)\n")
	} else {
		fmt.Printf("  direct ip : %s\n", bind)
	}
	fmt.Printf("  pair code : %s\n", currentCode())
	fmt.Printf("  save to   : %s\n", cfgDir)
	if c := snapConfig(); len(c.Peers) == 0 {
		fmt.Println("  target    : (未配置, 首次打开页面添加一次对端)")
	} else if p, ok := findPeer(c.Active); ok {
		fmt.Printf("  target    : %s (%s:%d), 共 %d 个已保存\n", p.Alias, p.IP, p.Port, len(c.Peers))
	}
	if list := addrList(); len(list) > 0 {
		var parts []string
		for _, a := range list {
			parts = append(parts, a.IP+" ["+a.Iface+"]")
		}
		fmt.Printf("  all ipv4  : %s\n", strings.Join(parts, ", "))
	}
	fmt.Println("  --------------------------------------------------")
	fmt.Printf("  open      : http://localhost:%d\n", cfgPort)
	if runtime.GOOS == "windows" {
		fmt.Println("")
		fmt.Println("  Keep this window open. Closing it stops the service.")
	}
	fmt.Println("")
}

// printWarnings 在启动时把两类必须让人看见的情况打印出来。
func printWarnings() {
	bind := currentLAN()
	switch {
	case bind == "":
		fmt.Println("  NOTE: 未选择直连地址, 服务仅在本机回环可用, 对端连不上。")
		fmt.Println("        在网页「设置 → 直连网卡」里选择插着对端网线的那块网卡, 点「保存」。")
		fmt.Println("")
	case !strings.HasPrefix(bind, linkLocal):
		fmt.Println("  NOTE: 当前绑定的是常规网段地址 " + bind + " (静态 IP / 手动指定)。")
		fmt.Println("        请确认内网线已拔下, 且这块网卡只连着对端机器。")
		fmt.Println("        插回内网线之前, 先关闭本程序。")
		fmt.Println("")
	}
	if len(snapConfig().Peers) == 0 {
		fmt.Println("  NOTE: 尚未保存任何对端。首次使用请在页面里填一次「别名 + IP + 对方配对码」,")
		fmt.Println("        之后每次只需把文件拖进窗口即可发送。")
		fmt.Println("")
	}
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

func openDir(path string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", path)
	case "windows":
		cmd = exec.Command("explorer", path)
	default:
		cmd = exec.Command("xdg-open", path)
	}
	_ = cmd.Start()
}

// ---------------------------------------------------------------- 鉴权

func auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if isLocalRequest(r) {
			next(w, r)
			return
		}
		ts := r.Header.Get("X-Ts")
		sig := r.Header.Get("X-Sig")
		if ts == "" || sig == "" || !verifySig(currentCode(), r.Method, r.URL.Path, ts, sig) {
			writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
				"error": "unauthorized: pair code mismatch or signature expired",
			})
			return
		}
		next(w, r)
	}
}

func verifySig(psk, method, path, tsStr, sig string) bool {
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false
	}
	now := time.Now().Unix()
	if ts < now-signWindow || ts > now+signWindow {
		return false
	}
	mac := hmac.New(sha256.New, []byte(psk))
	io.WriteString(mac, method+"\n"+path+"\n"+tsStr)
	want := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(sig))
}

func isLocalRequest(r *http.Request) bool {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	return isLocalIP(host)
}

// ---------------------------------------------------------------- 处理函数

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := uiFS.ReadFile("ui/index.html")
	if err != nil {
		http.Error(w, "ui not embedded", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(data)
}

func handleInfo(w http.ResponseWriter, r *http.Request) {
	refreshAddrs() // 插拔网线后地址会变, 每次取信息都重扫一次
	resp := map[string]interface{}{
		"name":    cfgName,
		"ip":      currentLAN(),
		"port":    cfgPort,
		"dir":     cfgDir,
		"version": appVersion,
		"allIPs":  addrList(),
	}
	if isLocalRequest(r) {
		resp["history"] = listHistory()
		resp["uploads"] = activeUploads()
	}
	writeJSON(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------- 配置 / 探测 / 发送代理

// handleConfig 只在响应本机 UI 时生效。GET 返回全部设置与本机网卡信息,
// POST 全量保存, 并在 bind 变化时即时切换直连监听器。
func handleConfig(w http.ResponseWriter, r *http.Request) {
	if !isLocalRequest(r) {
		writeJSON(w, http.StatusForbidden, map[string]interface{}{"error": "local access only"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		refreshAddrs()
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"config":  snapConfig(),
			"name":    cfgName,
			"dir":     cfgDir,
			"port":    cfgPort,
			"ip":      currentLAN(),
			"allIPs":  addrList(),
			"version": appVersion,
		})
	case http.MethodPost:
		var c Config
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&c); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "bad json: " + err.Error()})
			return
		}
		if err := validateConfig(&c); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
			return
		}
		refreshAddrs()
		if c.Bind != "" && !isLocalIP(c.Bind) {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"error":  "address not on this machine: " + c.Bind,
				"allIPs": addrList(),
			})
			return
		}
		// 只有直连地址真的变了才重建监听器。无条件重建会关掉旧 listener,
		// 把此刻正在进来的对端连接直接掐断(表现为 EOF), 而「保存并测试」
		// 恰好是 POST 完立刻探测, 极易撞上。
		want := c.Bind
		if want == "127.0.0.1" {
			want = ""
		}
		if want != currentLAN() {
			if err := setLANListener(want); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": "listen: " + err.Error()})
				return
			}
		}
		setCode(c.Code)
		cfgMu.Lock()
		curCfg = c
		cfgMu.Unlock()
		if err := writeConfig(c); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": "save config: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "config": snapConfig()})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "GET or POST required"})
	}
}

// signFor 用保存的配对码为发往对端的请求生成签名头, 与 auth/verifySig 格式一致。
func signFor(psk, method, p string) (string, string) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(psk))
	io.WriteString(mac, method+"\n"+p+"\n"+ts)
	return ts, hex.EncodeToString(mac.Sum(nil))
}

func withSig(req *http.Request, psk, method, p string) {
	ts, sig := signFor(psk, method, p)
	req.Header.Set("X-Ts", ts)
	req.Header.Set("X-Sig", sig)
}

func peerURL(peer Peer, uri string) string {
	return "http://" + net.JoinHostPort(peer.IP, strconv.Itoa(peer.Port)) + uri
}

// handleProbe 探测某个已保存对端是否在线、配对码是否正确。
// peerTransport 强制直连对端, 忽略系统/环境代理。
// 目标恒为配置中的 IPv4 字面量; 若被 HTTP_PROXY 或系统透明代理接管,
// 请求会被发到无关主机, 既连不通也把流量带离了这条隔离链路。
var peerTransport = &http.Transport{
	Proxy: nil,
	DialContext: (&net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext,
	MaxIdleConns:    8,
	IdleConnTimeout: 30 * time.Second,
}

func handleProbe(w http.ResponseWriter, r *http.Request) {
	if !isLocalRequest(r) {
		writeJSON(w, http.StatusForbidden, map[string]interface{}{"error": "local access only"})
		return
	}
	p, ok := findPeer(r.URL.Query().Get("id"))
	if !ok {
		writeJSON(w, http.StatusOK, map[string]interface{}{"state": "none"})
		return
	}
	// 本机是否已在直连网卡上监听。没有的话即使能探测到对端, 也只是单向可达:
	// 对端反过来连不进来, 表现为「A 显示已连接、B 却连不上 A」。
	selfIP := currentLAN()
	path := "/api/info"
	req, _ := http.NewRequest(http.MethodGet, peerURL(p, path), nil)
	withSig(req, p.Code, http.MethodGet, path)
	// 探测超时必须大于 peerTransport 的 5s 拨号超时。旧的 1.5s 会在网卡
	// 唤醒、首次 ARP、防火墙初次放行时误报 offline, 让人误以为链路断了。
	client := &http.Client{Timeout: 8 * time.Second, Transport: peerTransport}
	res, err := client.Do(req)
	if err != nil {
		// 把底层错误原文带回去: EOF / i/o timeout / connection refused
		// 指向完全不同的故障层, 全部吞成 offline 会让人无从排查。
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"state": "offline", "alias": p.Alias, "detail": err.Error(),
		})
		return
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusUnauthorized {
		writeJSON(w, http.StatusOK, map[string]interface{}{"state": "badcode", "alias": p.Alias})
		return
	}
	if res.StatusCode != http.StatusOK {
		writeJSON(w, http.StatusOK, map[string]interface{}{"state": "error", "alias": p.Alias, "status": res.StatusCode})
		return
	}
	var d struct {
		Name string `json:"name"`
		IP   string `json:"ip"`
	}
	_ = json.NewDecoder(io.LimitReader(res.Body, 1<<16)).Decode(&d)
	st := "ok"
	if selfIP == "" {
		st = "oneway"
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"state": st, "alias": p.Alias, "name": d.Name, "ip": d.IP,
		"selfIP": selfIP,
	})
}

// handleSend 接收浏览器上传的单个文件裸流, 边收边转发给已保存的对端。
// 浏览器只与 127.0.0.1 通信, 配对码不会出现在页面里。
func handleSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "POST required"})
		return
	}
	if !isLocalRequest(r) {
		writeJSON(w, http.StatusForbidden, map[string]interface{}{"error": "local access only"})
		return
	}
	q := r.URL.Query()
	p, ok := findPeer(q.Get("peer"))
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "未选择对端, 请先在设置里添加"})
		return
	}
	name := safeName(q.Get("name"))
	size, err := strconv.ParseInt(q.Get("size"), 10, 64)
	if err != nil || size < 0 || size > maxFileSize {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "文件大小无效或超过 2 GiB"})
		return
	}

	client := &http.Client{Timeout: 10 * time.Minute, Transport: peerTransport}

	// 1) 向对端声明本次会话
	initPath := "/api/recv/init"
	decl, _ := json.Marshal(map[string]interface{}{
		"files": []FileMeta{{Name: name, Size: size}},
	})
	req, _ := http.NewRequest(http.MethodPost, peerURL(p, initPath), bytes.NewReader(decl))
	req.Header.Set("Content-Type", "application/json")
	withSig(req, p.Code, http.MethodPost, initPath)
	res, err := client.Do(req)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]interface{}{"error": "连不上对端: " + err.Error()})
		return
	}
	var initOut struct {
		ID    string `json:"id"`
		Error string `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(res.Body, 1<<16)).Decode(&initOut)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || initOut.ID == "" {
		msg := initOut.Error
		if msg == "" {
			msg = "对端返回 HTTP " + strconv.Itoa(res.StatusCode) + "（配对码是否正确？）"
		}
		writeJSON(w, http.StatusBadGateway, map[string]interface{}{"error": msg})
		return
	}

	// 2) 裸流直转, 不在本机落盘
	blobPath := "/api/recv/blob/" + initOut.ID + "/0"
	req2, _ := http.NewRequest(http.MethodPut, peerURL(p, blobPath), r.Body)
	req2.ContentLength = size
	req2.Header.Set("Content-Type", "application/octet-stream")
	withSig(req2, p.Code, http.MethodPut, blobPath)
	res2, err := client.Do(req2)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]interface{}{"error": "传输中断: " + err.Error()})
		return
	}
	defer res2.Body.Close()
	var out map[string]interface{}
	_ = json.NewDecoder(io.LimitReader(res2.Body, 1<<16)).Decode(&out)
	if res2.StatusCode != http.StatusOK {
		msg, _ := out["error"].(string)
		if msg == "" {
			msg = "对端返回 HTTP " + strconv.Itoa(res2.StatusCode)
		}
		writeJSON(w, http.StatusBadGateway, map[string]interface{}{"error": msg})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "name": name, "size": size, "alias": p.Alias, "path": out["path"],
	})
}

// handleInit 声明一批待传文件, 返回会话 ID。
func handleInit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "POST required"})
		return
	}
	var req struct {
		Files []FileMeta `json:"files"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "bad json: " + err.Error()})
		return
	}
	if len(req.Files) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "no files declared"})
		return
	}
	if len(req.Files) > maxFiles {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "too many files in one batch"})
		return
	}

	u := &Upload{
		ID:      randomID(),
		Files:   make([]FileMeta, len(req.Files)),
		Written: make([]int64, len(req.Files)),
		Started: time.Now(),
		From:    remoteIP(r),
	}
	for i, f := range req.Files {
		if f.Size < 0 || f.Size > maxFileSize {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "file size out of range"})
			return
		}
		f.Name = safeName(f.Name)
		u.Files[i] = f
		u.Total += f.Size
	}

	storeMu.Lock()
	uploads[u.ID] = u
	storeMu.Unlock()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":  u.ID,
		"dir": cfgDir,
	})
}

// handleBlob 接收单个文件的裸字节流: PUT /api/recv/blob/{uploadId}/{index}
func handleBlob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "PUT required"})
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/recv/blob/")
	parts := strings.Split(rest, "/")
	if len(parts) != 2 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "bad path"})
		return
	}
	id := parts[0]
	idx, err := strconv.Atoi(parts[1])
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "bad index"})
		return
	}

	storeMu.RLock()
	u := uploads[id]
	storeMu.RUnlock()
	if u == nil {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{"error": "unknown upload id"})
		return
	}
	if idx < 0 || idx >= len(u.Files) {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "index out of range"})
		return
	}

	name := u.Files[idx].Name
	dst := uniquePath(cfgDir, name)

	f, err := os.Create(dst)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": "create file: " + err.Error()})
		return
	}
	defer f.Close()

	r.Body = http.MaxBytesReader(w, r.Body, maxFileSize)
	pw := &progressWriter{w: f, u: u, idx: idx}
	written, copyErr := io.Copy(pw, r.Body)
	pw.flush()

	if copyErr != nil {
		f.Close()
		os.Remove(dst)
		u.setErr(copyErr.Error())
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": "write failed: " + copyErr.Error()})
		return
	}
	if err := f.Sync(); err != nil {
		log.Printf("sync %s: %v", dst, err)
	}

	// 大小校验: 声明大小与实际写入不一致时视为失败, 避免半截文件被误认为成功。
	expected := u.Files[idx].Size
	if expected > 0 && written != expected {
		os.Remove(dst)
		msg := fmt.Sprintf("size mismatch: expected %d, got %d", expected, written)
		u.setErr(msg)
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": msg})
		return
	}

	u.markFileDone(idx, written)
	if u.allDone() {
		u.finish()
		u.archive()
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":      true,
		"written": written,
		"path":    dst,
	})
}

// handleStatus 返回会话进度, 供接收方 UI 轮询。
func handleStatus(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/recv/status/")
	storeMu.RLock()
	u := uploads[id]
	storeMu.RUnlock()
	if u == nil {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{"error": "unknown upload id"})
		return
	}
	writeJSON(w, http.StatusOK, u.snapshot())
}

// ---------------------------------------------------------------- Upload 状态

type progressWriter struct {
	w   io.Writer
	u   *Upload
	idx int
	buf int64
}

func (p *progressWriter) Write(b []byte) (int, error) {
	n, err := p.w.Write(b)
	p.buf += int64(n)
	if p.buf >= 256<<10 {
		p.u.addWritten(p.idx, p.buf)
		p.buf = 0
	}
	return n, err
}

func (p *progressWriter) flush() {
	if p.buf > 0 {
		p.u.addWritten(p.idx, p.buf)
		p.buf = 0
	}
}

func (u *Upload) addWritten(idx int, n int64) {
	u.mu.Lock()
	u.Written[idx] += n
	u.mu.Unlock()
}

func (u *Upload) markFileDone(idx int, total int64) {
	u.mu.Lock()
	u.Written[idx] = total
	u.mu.Unlock()
}

func (u *Upload) setErr(msg string) {
	u.mu.Lock()
	u.Err = msg
	u.Done = true
	u.mu.Unlock()
}

func (u *Upload) allDone() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	for i := range u.Files {
		if u.Written[i] < u.Files[i].Size {
			return false
		}
	}
	return true
}

func (u *Upload) finish() {
	u.mu.Lock()
	u.Done = true
	u.mu.Unlock()
}

func (u *Upload) archive() {
	histMu.Lock()
	for _, f := range u.Files {
		hist = append(hist, HistEntry{Name: f.Name, Size: f.Size, At: time.Now(), From: u.From})
	}
	if len(hist) > 50 {
		hist = hist[len(hist)-50:]
	}
	histMu.Unlock()
}

func (u *Upload) snapshot() map[string]interface{} {
	u.mu.Lock()
	defer u.mu.Unlock()
	var sum int64
	files := make([]map[string]interface{}, 0, len(u.Files))
	for i, f := range u.Files {
		sum += u.Written[i]
		files = append(files, map[string]interface{}{
			"name":    f.Name,
			"size":    f.Size,
			"written": u.Written[i],
			"done":    u.Written[i] >= f.Size,
		})
	}
	return map[string]interface{}{
		"id":      u.ID,
		"from":    u.From,
		"files":   files,
		"total":   u.Total,
		"written": sum,
		"done":    u.Done,
		"error":   u.Err,
		"started": u.Started.Unix(),
	}
}

func activeUploads() []map[string]interface{} {
	storeMu.RLock()
	defer storeMu.RUnlock()
	out := make([]map[string]interface{}, 0, len(uploads))
	for _, u := range uploads {
		out = append(out, u.snapshot())
		if len(out) >= 10 {
			break
		}
	}
	return out
}

func listHistory() []HistEntry {
	histMu.Lock()
	defer histMu.Unlock()
	out := make([]HistEntry, len(hist))
	copy(out, hist)
	// 倒序: 最新的在前
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	if len(out) > 20 {
		out = out[:20]
	}
	return out
}

// ---------------------------------------------------------------- 工具

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func remoteIP(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

// safeName 剥离路径成分与控制字符, 防止路径穿越与非法文件名。
// 先把两种分隔符统一为 '/' 再用 path.Base 处理, 使行为在 Windows 与 Unix 上一致。
func safeName(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	name = path.Base(name)
	name = strings.TrimSpace(name)
	var b strings.Builder
	for _, r := range name {
		if r < 32 || r == 127 {
			continue
		}
		b.WriteRune(r)
	}
	name = b.String()
	if name == "" || name == "." || name == ".." {
		name = "unnamed"
	}
	runes := []rune(name)
	if len(runes) > 120 {
		name = string(runes[:120])
	}
	return name
}

func uniquePath(dir, name string) string {
	p := filepath.Join(dir, name)
	if _, err := os.Stat(p); os.IsNotExist(err) {
		return p
	}
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	for i := 1; i < 1000; i++ {
		p = filepath.Join(dir, fmt.Sprintf("%s-%d%s", base, i, ext))
		if _, err := os.Stat(p); os.IsNotExist(err) {
			return p
		}
	}
	return filepath.Join(dir, fmt.Sprintf("%s-%d%s", base, time.Now().UnixNano(), ext))
}

func randomID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b)
}

func randomCode() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "000000"
	}
	n := int64(b[0])<<24 | int64(b[1])<<16 | int64(b[2])<<8 | int64(b[3])
	if n < 0 {
		n = -n
	}
	return fmt.Sprintf("%06d", n%1000000)
}
