package egressproxy_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oagentkit/guardx/egressproxy"
)

// 本文件钉 guardx#96 的回归：Permit 只判主机名不解析 DNS——放行名单里的
// 域名解析到私网/链路本地/云元数据时照转（egress#60 同款洞在代理层复现）。
// 修后：Permit / PermitResolving 对非 IP 字面量主机先解析、全部解析结果
// 逐个过 IP 围栏、解析失败/空结果 fail-closed，并返回已检地址供拨号钉住。

// stubResolver 固定解析结果的注入 stub（绕开真实网络），带调用计数——
// 「字面量不解析 / SkipDNSCheck 不解析」要用它断言。
type stubResolver struct {
	ips   []net.IP
	err   error
	calls atomic.Int32
}

func (s *stubResolver) LookupIP(context.Context, string, string) ([]net.IP, error) {
	s.calls.Add(1)
	if s.err != nil {
		return nil, s.err
	}
	return s.ips, nil
}

// TestPermitResolvesBeforeAllowing issue 实测复现场景：允许名单命中的域名
// 解析到云元数据——修前 Permit 返回 nil（照转），修后必须拒绝。
func TestPermitResolvesBeforeAllowing(t *testing.T) {
	res := &stubResolver{ips: []net.IP{net.ParseIP("169.254.169.254")}}
	p := egressproxy.Policy{
		AllowHosts: []string{"*.example.com"},
		Resolver:   res,
	}
	if err := p.Permit("a.example.com", 443); err == nil {
		t.Fatal("解析到云元数据（169.254.169.254）的域名必须被拒（#96）")
	}
	if res.calls.Load() == 0 {
		t.Fatal("Permit 应已介入解析（DNS 围栏缺位）")
	}
}

// TestPermitResolvingChecksEveryResolvedIP 全部解析结果逐个过 IP 围栏：
// 任一解析结果命中私网/链路本地/云元数据/组播即整条拒绝。
func TestPermitResolvingChecksEveryResolvedIP(t *testing.T) {
	cases := []struct {
		name string
		ip   string
	}{
		{"IPv4 私网", "10.0.0.5"},
		{"IPv4 私网 172 段", "172.16.0.9"},
		{"IPv4 私网 192 段", "192.168.1.9"},
		{"云元数据", "169.254.169.254"},
		{"CGNAT", "100.64.0.1"},
		{"组播", "224.0.0.1"},
		{"IPv6 ULA", "fd00::5"},
		{"IPv6 链路本地", "fe80::1"},
	}
	for _, tc := range cases {
		res := &stubResolver{ips: []net.IP{
			net.ParseIP("93.184.216.34"), // 首个结果公网——同批混入坏地址仍须拒绝
			net.ParseIP(tc.ip),
		}}
		p := egressproxy.Policy{AllowHosts: []string{"*.example.com"}, Resolver: res}
		if _, err := p.PermitResolving(context.Background(), "a.example.com", 443); err == nil {
			t.Errorf("%s: 解析结果含 %s 必须整条拒绝（修前只判主机名会放行）", tc.name, tc.ip)
		}
	}
}

// TestPermitResolvingAllowsPublicReturnCheckedAddrs 公网解析放行，并返回
// 全部已检地址（供拨号钉住、闭合 check/use TOCTOU）。
func TestPermitResolvingAllowsPublicReturnCheckedAddrs(t *testing.T) {
	ips := []net.IP{
		net.ParseIP("93.184.216.34"),
		net.ParseIP("2606:2800:220:1:248:1893:25c8:1946"),
	}
	res := &stubResolver{ips: ips}
	p := egressproxy.Policy{AllowHosts: []string{"*.example.com"}, Resolver: res}
	addrs, err := p.PermitResolving(context.Background(), "a.example.com", 443)
	if err != nil {
		t.Fatalf("公网解析结果应放行: %v", err)
	}
	if len(addrs) != len(ips) {
		t.Fatalf("应返回全部已检地址: %v", addrs)
	}
	for i, ip := range ips {
		if addrs[i].String() != ip.String() {
			t.Errorf("已检地址[%d] = %s，应为 %s", i, addrs[i], ip)
		}
	}
}

// TestPermitResolvingFailClosed 解析失败与空结果都必须阻断——「解析不出来」
// 与「解析到禁止 IP」都是不可放行的未知。
func TestPermitResolvingFailClosed(t *testing.T) {
	resErr := &stubResolver{err: context.DeadlineExceeded}
	p := egressproxy.Policy{AllowHosts: []string{"*.example.com"}, Resolver: resErr}
	if _, err := p.PermitResolving(context.Background(), "a.example.com", 443); err == nil {
		t.Fatal("解析失败必须 fail-closed")
	}
	resEmpty := &stubResolver{} // 空结果
	p2 := egressproxy.Policy{AllowHosts: []string{"*.example.com"}, Resolver: resEmpty}
	if _, err := p2.PermitResolving(context.Background(), "a.example.com", 443); err == nil {
		t.Fatal("解析结果为空必须 fail-closed")
	}
}

// TestPermitResolvingLiteralHostSkipsResolver IP 字面量走名单判定（名单即
// 调用方的显式意图），不触发解析。
func TestPermitResolvingLiteralHostSkipsResolver(t *testing.T) {
	res := &stubResolver{}
	p := egressproxy.Policy{AllowHosts: []string{"127.0.0.1"}, Resolver: res}
	addrs, err := p.PermitResolving(context.Background(), "127.0.0.1", 443)
	if err != nil {
		t.Fatalf("字面量命中名单应放行: %v", err)
	}
	if len(addrs) != 1 || addrs[0].String() != "127.0.0.1" {
		t.Fatalf("字面量应返回自身作为已检地址: %v", addrs)
	}
	if res.calls.Load() != 0 {
		t.Fatal("字面量不得触发解析")
	}
}

// TestPermitResolvingSkippableExplicitly SkipDNSCheck 是显式轻量档：只看
// 主机名，不解析（缺省仍是解析 + fail-closed）。
func TestPermitResolvingSkippableExplicitly(t *testing.T) {
	res := &stubResolver{}
	p := egressproxy.Policy{
		AllowHosts:   []string{"*.example.com"},
		SkipDNSCheck: true,
		Resolver:     res,
	}
	if err := p.Permit("a.example.com", 443); err != nil {
		t.Fatalf("显式跳过 DNS 检查时应按主机名放行: %v", err)
	}
	if res.calls.Load() != 0 {
		t.Fatal("SkipDNSCheck 不得触发解析")
	}
}

// TestPermitNameChecksStillFirst 名单/端口判定先于解析：不合法目标不触发
// 任何 DNS 查询。
func TestPermitNameChecksStillFirst(t *testing.T) {
	res := &stubResolver{}
	p := egressproxy.Policy{
		DenyHosts:  []string{"b.example.com"},
		AllowHosts: []string{"*.example.com"},
		Resolver:   res,
	}
	if err := p.Permit("b.example.com", 443); err == nil {
		t.Fatal("拒绝名单必须优先")
	}
	if err := p.Permit("c.example.com", 8080); err == nil {
		t.Fatal("端口不在放行端口内必须拒绝")
	}
	if res.calls.Load() != 0 {
		t.Fatal("名单/端口未过的目标不得触发解析")
	}
}

// TestConnectBlockedWhenResolutionHitsPrivate 端到端：CONNECT 的目标域名
// 解析到云元数据——必须 403 拒绝（带 X-Egress-Blocked 头）且不拨号。
func TestConnectBlockedWhenResolutionHitsPrivate(t *testing.T) {
	// 本地假目标：若代理在 DNS 围栏前放行，就会连上它——围栏必须先行。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	targetConnCh := make(chan net.Conn, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			targetConnCh <- c
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	res := &stubResolver{ips: []net.IP{net.ParseIP("169.254.169.254")}}
	proxy := startProxy(t, egressproxy.Policy{
		AllowHosts: []string{"target.test"},
		AllowPorts: []int{port},
		Resolver:   res,
	})

	conn, err := net.Dial("tcp", proxy.Host)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	hostport := "target.test:" + strconv.Itoa(port)
	if _, err := conn.Write([]byte("CONNECT " + hostport + " HTTP/1.1\r\nHost: " + hostport + "\r\n\r\n")); err != nil {
		t.Fatalf("write connect: %v", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("解析到云元数据的域名被放行（#96 洞在代理层复现）")
	}
	if resp.Header.Get("X-Egress-Blocked") == "" {
		t.Errorf("拒绝响应应带 X-Egress-Blocked 原因头，实得 %v", resp.Header)
	}
	select {
	case c := <-targetConnCh:
		t.Fatalf("被拒目标不应被拨号：假目标收到了 %v 的连接", c.RemoteAddr())
	default:
	}
}

// TestForwardBlockedWhenResolutionHitsPrivate 端到端：明文转发的目标域名
// 解析到私网——必须 403 拒绝且不触达源站。
func TestForwardBlockedWhenResolutionHitsPrivate(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "should-not-be-reached")
	}))
	defer origin.Close()

	res := &stubResolver{ips: []net.IP{net.ParseIP("10.0.0.5")}}
	proxy := startProxy(t, egressproxy.Policy{
		AllowHosts: []string{"target.test"},
		AllowPorts: []int{originPort(t, origin.URL)},
		Resolver:   res,
	})

	req, err := http.NewRequest(http.MethodGet, "http://target.test:"+strconv.Itoa(originPort(t, origin.URL))+"/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := plainClient(proxy).Do(req)
	if err != nil {
		t.Fatalf("经代理请求: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(resp.Header.Get("X-Egress-Blocked"), "DNS") {
		t.Fatalf("解析到私网的域名应 403 + DNS 围栏原因，实得 %d / %q / body=%q",
			resp.StatusCode, resp.Header.Get("X-Egress-Blocked"), body)
	}
	if strings.Contains(string(body), "should-not-be-reached") {
		t.Fatal("源站不应被触达")
	}
}
