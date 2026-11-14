package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func sign(psk, method, path, ts string) string {
	m := hmac.New(sha256.New, []byte(psk))
	io.WriteString(m, method+"\n"+path+"\n"+ts)
	return hex.EncodeToString(m.Sum(nil))
}

func TestVerifySig(t *testing.T) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	good := sign("123456", "PUT", "/api/recv/blob/a/0", ts)

	if !verifySig("123456", "PUT", "/api/recv/blob/a/0", ts, good) {
		t.Fatal("valid signature rejected")
	}
	if verifySig("654321", "PUT", "/api/recv/blob/a/0", ts, good) {
		t.Fatal("wrong pair code accepted")
	}
	if verifySig("123456", "PUT", "/api/recv/blob/a/1", ts, good) {
		t.Fatal("path tampering accepted")
	}
	old := strconv.FormatInt(time.Now().Unix()-3600, 10)
	if verifySig("123456", "PUT", "/api/recv/blob/a/0", old, sign("123456", "PUT", "/api/recv/blob/a/0", old)) {
		t.Fatal("expired timestamp accepted")
	}
}

func TestSafeName(t *testing.T) {
	cases := map[string]string{
		"../../etc/passwd":    "passwd",
		`..\..\windows\a.exe`: "a.exe",
		"/tmp/x.txt":          "x.txt",
		"normal file.pdf":     "normal file.pdf",
		"":                    "unnamed",
		"..":                  "unnamed",
		"a\x00b.txt":          "ab.txt",
	}
	for in, want := range cases {
		if got := safeName(in); got != want {
			t.Errorf("safeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAuthRejectsNonLocal(t *testing.T) {
	cfgCode = "999888"
	cfgDir = t.TempDir()
	localIPs = map[string]bool{"127.0.0.1": true}

	h := auth(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })

	req := httptest.NewRequest("GET", "/api/info", nil)
	req.RemoteAddr = "169.254.7.7:5555"
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("remote without signature got %d, want 401", rec.Code)
	}

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req2 := httptest.NewRequest("GET", "/api/info", nil)
	req2.RemoteAddr = "169.254.7.7:5555"
	req2.Header.Set("X-Ts", ts)
	req2.Header.Set("X-Sig", sign("999888", "GET", "/api/info", ts))
	rec2 := httptest.NewRecorder()
	h(rec2, req2)
	if rec2.Code != 200 {
		t.Fatalf("remote with valid signature got %d, want 200", rec2.Code)
	}

	req3 := httptest.NewRequest("GET", "/api/info", nil)
	req3.RemoteAddr = "127.0.0.1:5555"
	rec3 := httptest.NewRecorder()
	h(rec3, req3)
	if rec3.Code != 200 {
		t.Fatalf("local request got %d, want 200", rec3.Code)
	}
}

func TestEndToEndUpload(t *testing.T) {
	cfgCode = "111111"
	cfgDir = t.TempDir()
	cfgName = "test"
	localIPs = map[string]bool{"127.0.0.1": true}
	uploads = map[string]*Upload{}
	hist = nil

	mux := http.NewServeMux()
	mux.HandleFunc("/api/info", auth(handleInfo))
	mux.HandleFunc("/api/recv/init", auth(handleInit))
	mux.HandleFunc("/api/recv/blob/", auth(handleBlob))
	mux.HandleFunc("/api/recv/status/", auth(handleStatus))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	payload := bytes.Repeat([]byte("WBDROP-PAYLOAD-"), 10000) // ~140 KB

	body, _ := json.Marshal(map[string]interface{}{
		"files": []map[string]interface{}{{"name": "测试 文件.bin", "size": len(payload)}},
	})
	res, err := http.Post(srv.URL+"/api/recv/init", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var init struct {
		ID  string `json:"id"`
		Dir string `json:"dir"`
	}
	json.NewDecoder(res.Body).Decode(&init)
	res.Body.Close()
	if init.ID == "" {
		t.Fatalf("no upload id, status %d", res.StatusCode)
	}

	req, _ := http.NewRequest("PUT", srv.URL+"/api/recv/blob/"+init.ID+"/0", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/octet-stream")
	pres, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	pres.Body.Close()
	if pres.StatusCode != 200 {
		t.Fatalf("blob put status %d", pres.StatusCode)
	}

	// 状态查询
	sres, _ := http.Get(srv.URL + "/api/recv/status/" + init.ID)
	var snap map[string]interface{}
	json.NewDecoder(sres.Body).Decode(&snap)
	sres.Body.Close()
	if snap["done"] != true {
		t.Fatalf("upload not marked done: %v", snap)
	}

	// 落盘校验
	files, _ := filepath.Glob(filepath.Join(cfgDir, "*"))
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %v", files)
	}
	got, _ := os.ReadFile(files[0])
	if !bytes.Equal(got, payload) {
		t.Fatalf("content mismatch: got %d bytes want %d", len(got), len(payload))
	}
	if filepath.Base(files[0]) != "测试 文件.bin" {
		t.Fatalf("unexpected filename %q", filepath.Base(files[0]))
	}

	// 重名应自动加后缀, 不覆盖
	dst := uniquePath(cfgDir, "测试 文件.bin")
	if !strings.Contains(dst, "-1") {
		t.Fatalf("duplicate not renamed: %s", dst)
	}

	// 大小不符必须拒绝并清理半截文件
	body2, _ := json.Marshal(map[string]interface{}{
		"files": []map[string]interface{}{{"name": "short.bin", "size": 999999}},
	})
	r2, _ := http.Post(srv.URL+"/api/recv/init", "application/json", bytes.NewReader(body2))
	var init2 struct{ ID string }
	json.NewDecoder(r2.Body).Decode(&init2)
	r2.Body.Close()

	req2, _ := http.NewRequest("PUT", srv.URL+"/api/recv/blob/"+init2.ID+"/0", bytes.NewReader([]byte("tiny")))
	r2res, _ := http.DefaultClient.Do(req2)
	r2res.Body.Close()
	if r2res.StatusCode != http.StatusBadRequest {
		t.Fatalf("size mismatch should be 400, got %d", r2res.StatusCode)
	}
	if _, err := os.Stat(filepath.Join(cfgDir, "short.bin")); !os.IsNotExist(err) {
		t.Fatal("truncated file was not cleaned up")
	}
}

func TestIndexEmbedded(t *testing.T) {
	rec := httptest.NewRecorder()
	handleIndex(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 200 {
		t.Fatalf("index status %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "WBDrop") {
		t.Fatal("ui content missing")
	}
	fmt.Println("ui bytes:", rec.Body.Len())
}

// 配置接口只接受本机调用, 且 bind 必须是本机网卡地址。
func TestConfigRejectsForeignAddress(t *testing.T) {
	cfgPath = "" // 绝不写真实用户目录
	refreshAddrs()
	localIPs = map[string]bool{"127.0.0.1": true}
	curCfg = Config{Code: "123456", Peers: []Peer{}}

	post := func(body, remote string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/api/config", strings.NewReader(body))
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		handleConfig(rec, req)
		return rec
	}

	if rec := post(`{"code":"123456","bind":"10.9.9.9","peers":[]}`, "127.0.0.1:5555"); rec.Code != http.StatusBadRequest {
		t.Fatalf("foreign address got %d, want 400", rec.Code)
	}
	// 解绑是安全的, 不应尝试监听
	if rec := post(`{"code":"123456","bind":"","peers":[]}`, "127.0.0.1:5555"); rec.Code != http.StatusOK {
		t.Fatalf("unbind got %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if got := currentLAN(); got != "" {
		t.Fatalf("unbind left address %q", got)
	}
	// 非本机调用一律拒绝
	if rec := post(`{"code":"123456","bind":"","peers":[]}`, "169.254.9.9:5555"); rec.Code != http.StatusForbidden {
		t.Fatalf("remote config got %d, want 403", rec.Code)
	}
}

func TestValidateConfig(t *testing.T) {
	c := Config{Code: "  482913  ", Peers: []Peer{
		{Alias: "  内网机  ", IP: "10.20.30.40", Code: " 111222 "},
		{Alias: "Mac", IP: "169.254.1.2", Port: 18500, Code: "333444"},
	}}
	if err := validateConfig(&c); err != nil {
		t.Fatal(err)
	}
	if c.Code != "482913" || c.Peers[0].Alias != "内网机" || c.Peers[0].Port != defaultPort {
		t.Fatalf("normalize failed: %+v", c)
	}
	if c.Peers[0].ID == "" || c.Peers[1].ID == "" || c.Peers[0].ID == c.Peers[1].ID {
		t.Fatal("peer ids not generated uniquely")
	}
	if c.Active != c.Peers[0].ID {
		t.Fatal("active peer not defaulted to first")
	}

	bad := []Config{
		{Code: ""},
		{Code: "1", Peers: []Peer{{Alias: "x", IP: "host.example.com", Code: "1"}}}, // 拒绝主机名
		{Code: "1", Peers: []Peer{{Alias: "x", IP: "10.0.0.1", Port: 70000, Code: "1"}}},
		{Code: "1", Peers: []Peer{{Alias: "x", IP: "10.0.0.1", Code: ""}}},
	}
	for i, b := range bad {
		if err := validateConfig(&b); err == nil {
			t.Errorf("case %d should be rejected: %+v", i, b)
		}
	}
}

// 拖文件即发的完整链路: 浏览器 -> /api/send -> 签名转发 -> 对端落盘。
// 对端用独立的签名校验(不依赖 isLocalRequest), 确保后端生成的签名确实可用。
func TestSendProxyEndToEnd(t *testing.T) {
	cfgPath = ""
	cfgDir = t.TempDir()
	cfgName = "receiver"
	setCode("777888")
	localIPs = map[string]bool{"127.0.0.1": true}
	uploads = map[string]*Upload{}
	hist = nil

	signed := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !verifySig("777888", r.Method, r.URL.Path,
				r.Header.Get("X-Ts"), r.Header.Get("X-Sig")) {
				writeJSON(w, 401, map[string]interface{}{"error": "unauthorized"})
				return
			}
			next(w, r)
		}
	}
	peerMux := http.NewServeMux()
	peerMux.HandleFunc("/api/recv/init", signed(handleInit))
	peerMux.HandleFunc("/api/recv/blob/", signed(handleBlob))
	peerSrv := httptest.NewServer(peerMux)
	defer peerSrv.Close()

	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(peerSrv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)
	cfgMu.Lock()
	curCfg = Config{
		Code: "777888", Active: "p1",
		Peers: []Peer{{ID: "p1", Alias: "内网机", IP: host, Port: port, Code: "777888"}},
	}
	cfgMu.Unlock()

	localMux := http.NewServeMux()
	localMux.HandleFunc("/api/send", auth(handleSend))
	localSrv := httptest.NewServer(localMux)
	defer localSrv.Close()

	payload := bytes.Repeat([]byte("HELLO-WBDROP-"), 10000) // ~130 KB
	q := url.Values{"peer": {"p1"}, "name": {"报告 2026.bin"}, "size": {strconv.Itoa(len(payload))}}
	res, err := http.Post(localSrv.URL+"/api/send?"+q.Encode(),
		"application/octet-stream", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]interface{}
	_ = json.NewDecoder(res.Body).Decode(&out)
	res.Body.Close()
	if res.StatusCode != 200 || out["ok"] != true {
		t.Fatalf("send failed: HTTP %d %v", res.StatusCode, out)
	}
	if out["alias"] != "内网机" {
		t.Fatalf("wrong target: %v", out["alias"])
	}

	files, _ := filepath.Glob(filepath.Join(cfgDir, "*"))
	if len(files) != 1 {
		t.Fatalf("expected 1 received file, got %v", files)
	}
	if filepath.Base(files[0]) != "报告 2026.bin" {
		t.Fatalf("unexpected filename %q", filepath.Base(files[0]))
	}
	got, _ := os.ReadFile(files[0])
	if !bytes.Equal(got, payload) {
		t.Fatalf("content mismatch: got %d bytes, want %d", len(got), len(payload))
	}
	fmt.Println("send proxy e2e bytes:", len(got))
}

// 没有 169.254 地址时不得自动绑定任何常规网段地址, 必须留给用户显式选择。
func TestPickBindAddrOnlyLinkLocal(t *testing.T) {
	addrMu.Lock()
	allIPv4 = []IPv4Addr{{IP: "10.20.30.40", Iface: "en5"}, {IP: "192.168.1.8", Iface: "en0"}}
	addrMu.Unlock()
	if got := pickBindAddr(); got != "" {
		t.Fatalf("picked %q without link-local address, want empty", got)
	}

	addrMu.Lock()
	allIPv4 = []IPv4Addr{{IP: "10.20.30.40", Iface: "en5"}, {IP: "169.254.1.7", Iface: "en5"}}
	addrMu.Unlock()
	if got := pickBindAddr(); got != "169.254.1.7" {
		t.Fatalf("picked %q, want 169.254.1.7", got)
	}
}

// 回归: 空对端列表必须序列化成 [] 而不是 null。
// 曾因 snapConfig 用 append([]Peer(nil), empty...) 返回 nil, 导致前端
// state.cfg.peers.push 抛 TypeError, "保存并测试"静默失败。
func TestConfigPeersNeverNull(t *testing.T) {
	old := snapConfig()
	defer func() {
		cfgMu.Lock()
		curCfg = old
		cfgMu.Unlock()
	}()

	cfgMu.Lock()
	curCfg = Config{Code: "123456", Peers: []Peer{}}
	cfgMu.Unlock()

	b, err := json.Marshal(snapConfig())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"peers":[]`)) {
		t.Fatalf("empty peers serialized as null: %s", b)
	}

	// 前端若提交 null, 规范化后也不得写回 null。
	var c Config
	if err := json.Unmarshal([]byte(`{"code":"123456","peers":null}`), &c); err != nil {
		t.Fatal(err)
	}
	if err := validateConfig(&c); err != nil {
		t.Fatal(err)
	}
	b2, _ := json.Marshal(c)
	if !bytes.Contains(b2, []byte(`"peers":[]`)) {
		t.Fatalf("validateConfig left null peers: %s", b2)
	}
}

// 回归: 本机没有直连监听时, probe 必须报 oneway 而不是 ok, 否则会出现
// 「A 显示已连接、B 却连不上 A」这种单向故障而界面毫无提示。
func TestProbeReportsOneWay(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"name": "LAPTOP", "ip": "10.20.30.216",
		})
	}))
	defer peer.Close()

	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(peer.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)

	oldCfg := snapConfig()
	oldLocal := localIPs
	lanMu.Lock()
	oldLAN := lanIP
	lanMu.Unlock()
	defer func() {
		cfgMu.Lock()
		curCfg = oldCfg
		cfgMu.Unlock()
		localIPs = oldLocal
		lanMu.Lock()
		lanIP = oldLAN
		lanMu.Unlock()
	}()

	localIPs = map[string]bool{"127.0.0.1": true}
	cfgMu.Lock()
	curCfg = Config{
		Code: "111111", Active: "p1",
		Peers: []Peer{{ID: "p1", Alias: "内网", IP: host, Port: port, Code: "111111"}},
	}
	cfgMu.Unlock()

	call := func() string {
		req := httptest.NewRequest("GET", "/api/probe?id=p1", nil)
		req.RemoteAddr = "127.0.0.1:5555"
		rec := httptest.NewRecorder()
		handleProbe(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("probe HTTP %d", rec.Code)
		}
		var out map[string]interface{}
		if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		st, _ := out["state"].(string)
		return st
	}

	lanMu.Lock()
	lanIP = ""
	lanMu.Unlock()
	if got := call(); got != "oneway" {
		t.Fatalf("no direct listener: got %q, want oneway", got)
	}

	lanMu.Lock()
	lanIP = "10.20.30.116"
	lanMu.Unlock()
	if got := call(); got != "ok" {
		t.Fatalf("with direct listener: got %q, want ok", got)
	}
}

// 回归: USB 网卡掉线期间重启 WBDrop, 保存的直连地址不能被清空落盘。
func TestStartupBindDecisionKeepsSavedWhenOffline(t *testing.T) {
	const saved = "10.20.30.116"

	// saved 当前不属于本机(拔线 / 睡眠 / USB 网卡掉电): 本次不监听, 也不回写。
	lan, persist, offline := startupBindDecision("", saved, "169.254.1.2",
		func(ip string) bool { return ip == "10.100.3.86" })
	if lan != "" || persist || !offline {
		t.Fatalf("offline: lan=%q persist=%v offline=%v", lan, persist, offline)
	}

	// 网卡在线: 沿用保存地址, 且优先于自动采纳的 169.254 地址。
	lan, persist, offline = startupBindDecision("", saved, "169.254.1.2",
		func(ip string) bool { return ip == saved })
	if lan != saved || !persist || offline {
		t.Fatalf("online: lan=%q persist=%v offline=%v", lan, persist, offline)
	}

	// 命令行 -bind 优先级最高。
	lan, persist, offline = startupBindDecision("10.20.30.200", saved, "",
		func(string) bool { return true })
	if lan != "10.20.30.200" || !persist || offline {
		t.Fatalf("cli: lan=%q persist=%v offline=%v", lan, persist, offline)
	}

	// 从未保存过: 可以自动采纳链路本地地址, 也可以安全地写空。
	lan, persist, offline = startupBindDecision("", "", "169.254.1.2",
		func(string) bool { return true })
	if lan != "169.254.1.2" || !persist || offline {
		t.Fatalf("auto: lan=%q persist=%v offline=%v", lan, persist, offline)
	}
	lan, persist, offline = startupBindDecision("", "", "",
		func(string) bool { return true })
	if lan != "" || !persist || offline {
		t.Fatalf("empty: lan=%q persist=%v offline=%v", lan, persist, offline)
	}
}

// 回归: 探测失败必须把 Go 底层错误原文带回来。只回一个笼统的 offline
// 会让「EOF / i/o timeout / connection refused」这三种完全不同的故障
// 看起来一模一样, 现场根本无法定位。
func TestProbeOfflineIncludesDetail(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(dead.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)
	dead.Close() // 端口不再监听, 连接必然被拒绝

	oldCfg := snapConfig()
	oldLocal := localIPs
	defer func() {
		cfgMu.Lock()
		curCfg = oldCfg
		cfgMu.Unlock()
		localIPs = oldLocal
	}()
	localIPs = map[string]bool{"127.0.0.1": true}
	cfgMu.Lock()
	curCfg = Config{
		Code: "111111", Active: "p1",
		Peers: []Peer{{ID: "p1", Alias: "内网", IP: host, Port: port, Code: "111111"}},
	}
	cfgMu.Unlock()

	req := httptest.NewRequest("GET", "/api/probe?id=p1", nil)
	req.RemoteAddr = "127.0.0.1:5555"
	rec := httptest.NewRecorder()
	handleProbe(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("probe HTTP %d", rec.Code)
	}
	var out map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out["state"] != "offline" {
		t.Fatalf("state = %v, want offline", out["state"])
	}
	if detail, _ := out["detail"].(string); detail == "" {
		t.Fatal("detail missing: offline is hiding the underlying transport error")
	}
}

// 回归: 插线后自动恢复监听, 但不能覆盖已有监听、不能绑定未上线的地址、
// 也不能把 Wi-Fi 之类地址猜成直连网卡。
func TestRestoreTarget(t *testing.T) {
	cases := []struct {
		name, saved, current string
		local                bool
		want                 string
	}{
		{"never configured", "", "", true, ""},
		{"loopback is not a direct link", "127.0.0.1", "", true, ""},
		{"already listening", "10.20.30.116", "10.20.30.116", true, ""},
		{"address not back yet", "10.20.30.116", "", false, ""},
		{"cable back", "10.20.30.116", "", true, "10.20.30.116"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := restoreTarget(tc.saved, tc.current, tc.local); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
