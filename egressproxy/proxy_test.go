package egressproxy_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/oagentkit/guardx/egressproxy"
	"github.com/oagentkit/guardx/sandbox"
)

// startProxy 起一个代理并在用例结束时关掉。
func startProxy(t *testing.T, p egressproxy.Policy) *url.URL {
	t.Helper()
	px, err := egressproxy.New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	addr, err := px.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = px.Close() })
	u, err := url.Parse(addr)
	if err != nil {
		t.Fatalf("解析代理地址 %q: %v", addr, err)
	}
	return u
}

func originPort(t *testing.T, raw string) int {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("解析 origin 地址 %q: %v", raw, err)
	}
	var port int
	if _, err := fmtSscan(u.Port(), &port); err != nil {
		t.Fatalf("解析端口 %q: %v", u.Port(), err)
	}
	return port
}

func fmtSscan(s string, out *int) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errBadPort
		}
		n = n*10 + int(c-'0')
	}
	*out = n
	return 1, nil
}

var errBadPort = &portErr{}

type portErr struct{}

func (*portErr) Error() string { return "端口不是十进制数" }

func plainClient(proxy *url.URL) *http.Client {
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}}
}

// T1 放行名单命中的明文请求真的被转发（代理不是摆设）。
func TestForwardAllowed(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer origin.Close()
	proxy := startProxy(t, egressproxy.Policy{
		AllowHosts: []string{"127.0.0.1"},
		AllowPorts: []int{originPort(t, origin.URL)},
	})

	resp, err := plainClient(proxy).Get(origin.URL)
	if err != nil {
		t.Fatalf("经代理请求失败: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("期望 200，得到 %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Fatalf("响应体应 ok，得到 %q", body)
	}
}

// T2 未在名单内的目标默认拒绝，且拒绝理由是结构化的（不是目标自己的 403）。
func TestForwardDefaultDeny(t *testing.T) {
	proxy := startProxy(t, egressproxy.Policy{AllowHosts: []string{"allowed.example"}})
	resp, err := plainClient(proxy).Get("http://blocked.example/")
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("期望 403，得到 %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Egress-Blocked"); got == "" {
		t.Fatal("拒绝响应必须带 X-Egress-Blocked 原因头（否则与目标自己的 403 不可区分）")
	}
}

// T3 空放行名单 = 全拒（「没配置」不得被读成「放行」）。
func TestEmptyAllowListDeniesEverything(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()
	proxy := startProxy(t, egressproxy.Policy{AllowPorts: []int{originPort(t, origin.URL)}})
	resp, err := plainClient(proxy).Get(origin.URL)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("空名单必须全拒，得到 %d", resp.StatusCode)
	}
}

// T4 拒绝名单优先于放行名单。
func TestDenyWins(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()
	proxy := startProxy(t, egressproxy.Policy{
		AllowHosts: []string{"127.0.0.1"},
		DenyHosts:  []string{"127.0.0.1"},
		AllowPorts: []int{originPort(t, origin.URL)},
	})
	resp, err := plainClient(proxy).Get(origin.URL)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("拒绝名单必须优先，得到 %d", resp.StatusCode)
	}
}

// T5 端口不在放行端口内即拒（主机名单对了不等于可以连 22/3306）。
func TestPortNotAllowed(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()
	proxy := startProxy(t, egressproxy.Policy{
		AllowHosts: []string{"127.0.0.1"},
		AllowPorts: []int{1},
	})
	resp, err := plainClient(proxy).Get(origin.URL)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("端口未放行应拒，得到 %d", resp.StatusCode)
	}
}

// T6 只读模式：明文请求只放 GET/HEAD。
func TestLimitedMode(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer origin.Close()
	proxy := startProxy(t, egressproxy.Policy{
		AllowHosts: []string{"127.0.0.1"},
		AllowPorts: []int{originPort(t, origin.URL)},
		Limited:    true,
	})
	c := plainClient(proxy)

	post, err := c.Post(origin.URL, "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatalf("POST 失败: %v", err)
	}
	_ = post.Body.Close()
	if post.StatusCode != http.StatusForbidden {
		t.Fatalf("只读模式应拒 POST，得到 %d", post.StatusCode)
	}

	get, err := c.Get(origin.URL)
	if err != nil {
		t.Fatalf("GET 失败: %v", err)
	}
	_ = get.Body.Close()
	if get.StatusCode != http.StatusOK {
		t.Fatalf("只读模式应放 GET，得到 %d", get.StatusCode)
	}
}

// T7 CONNECT 隧道端到端：HTTPS 真的经代理出去（这是子进程最常见的形态）。
func TestConnectTunnelTLS(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "tls-ok")
	}))
	defer origin.Close()
	proxy := startProxy(t, egressproxy.Policy{
		AllowHosts: []string{"127.0.0.1"},
		AllowPorts: []int{originPort(t, origin.URL)},
	})

	c := origin.Client()
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("httptest 客户端的 Transport 形态变了: %T", c.Transport)
	}
	tr.Proxy = http.ProxyURL(proxy)

	resp, err := c.Get(origin.URL)
	if err != nil {
		t.Fatalf("经 CONNECT 隧道请求失败: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "tls-ok" {
		t.Fatalf("隧道内容应为 tls-ok，得到 %q", body)
	}
}

// T8 CONNECT 到未放行端口必须被拒（不能靠「隧道建起来了」冒充放行）。
func TestConnectDeniedPort(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()
	proxy := startProxy(t, egressproxy.Policy{
		AllowHosts: []string{"127.0.0.1"},
		AllowPorts: []int{1},
	})
	c := origin.Client()
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport 形态变了: %T", c.Transport)
	}
	tr.Proxy = http.ProxyURL(proxy)
	if _, err := c.Get(origin.URL); err == nil {
		t.Fatal("CONNECT 到未放行端口必须失败")
	}
}

// T9 能力声明：只能兑现 proxy，不得声称 denied。
func TestEnforcerDeclaration(t *testing.T) {
	px, err := egressproxy.New(egressproxy.Policy{AllowHosts: []string{"a.example"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var _ sandbox.EgressEnforcer = px // 接口一致性（词表在 tier 0 才可能成立）
	if got := px.Egress(); got != sandbox.EgressProxy {
		t.Fatalf("Egress() 应为 proxy，得到 %s", got)
	}
	if px.Egress().Satisfies(sandbox.EgressDenied) {
		t.Fatal("代理不得声称兑现 denied —— 绕开代理的原始 socket 它挡不住")
	}
}
