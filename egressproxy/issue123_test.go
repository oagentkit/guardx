package egressproxy_test

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/oagentkit/guardx/egressproxy"
)

// 本文件钉 guardx#123 的回归：IPv4-mapped IPv6 字面量（::ffff:x.x.x.x）进
// AllowHosts 后永远拨不出去—— PermitResolving 字面量路径返回的 netip.Addr
// 不做 Unmap（String() 恒为 ::ffff: 前缀形态），而 pinnedDial 的集合建在
// String()、Control 复核比对在 Unmap().String()（net 栈 Control 收到的就是
// 点分 v4 形态），两侧恒不相等 ⇒ 合法配置自我失能（PermitResolving 放行、
// 拨号面 100% 拒绝，CONNECT 得 502）。修后：字面量路径同样 Unmap，pinnedDial
// 集合键/拨号字面量/Control 比对三方统一 Unmap().String()。

// TestMappedIPv6LiteralReturnsUnmappedAddr 策略层：逐字名单命中的 mapped
// 字面量返回**裸 v4 形态**的已检地址（与 DNS 路径的归一口径一致）。
func TestMappedIPv6LiteralReturnsUnmappedAddr(t *testing.T) {
	p := egressproxy.Policy{AllowHosts: []string{"::ffff:93.184.216.34"}}
	addrs, err := p.PermitResolving(nil, "::ffff:93.184.216.34", 443)
	if err != nil {
		t.Fatalf("逐字名单条目应放行，实得 %v", err)
	}
	if len(addrs) != 1 || addrs[0] != netip.MustParseAddr("93.184.216.34") {
		t.Fatalf("mapped 字面量应归一为裸 v4 形态供拨号钉住，实得 %v（%s）", addrs, addrs[0].String())
	}
}

// TestPlainIPv6AndIPv4LiteralUnaffected 非 mapped 字面量不受影响：Unmap 对
// 纯 v4/v6 是恒等，返回地址形态照旧。
func TestPlainIPv6AndIPv4LiteralUnaffected(t *testing.T) {
	cases := []struct{ entry, host, want string }{
		{"93.184.216.34", "93.184.216.34", "93.184.216.34"},
		{"2001:db8::5", "2001:db8::5", "2001:db8::5"},
		{"::1", "::1", "::1"},
	}
	for _, tc := range cases {
		p := egressproxy.Policy{AllowHosts: []string{tc.entry}}
		addrs, err := p.PermitResolving(nil, tc.host, 443)
		if err != nil {
			t.Fatalf("%s 应放行，实得 %v", tc.host, err)
		}
		if len(addrs) != 1 || addrs[0].String() != tc.want {
			t.Fatalf("%s 应返回自身形态 %s，实得 %v", tc.host, tc.want, addrs)
		}
	}
}

// TestConnectViaMappedIPv6LiteralEndToEnd 端到端真拨号（issue 要求合入前
// 实拨确认）：AllowHosts 含 mapped 字面量、客户端 CONNECT 同一字面量——
// 修复前 pinnedDial 的 Control 复核恒判「不在已检地址集合内」→ 502；
// 修复后隧道建立、数据可达。
func TestConnectViaMappedIPv6LiteralEndToEnd(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			_, _ = io.WriteString(c, "mapped-ok")
			_ = c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	px, err := egressproxy.New(egressproxy.Policy{
		AllowHosts: []string{"::ffff:127.0.0.1"},
		AllowPorts: []int{port},
	})
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	listen, err := px.Start()
	if err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer func() { _ = px.Close() }()

	conn, err := net.Dial("tcp", listen[len("http://"):])
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	hostport := net.JoinHostPort("::ffff:127.0.0.1", strconv.Itoa(port))
	if _, err := conn.Write([]byte("CONNECT " + hostport + " HTTP/1.1\r\nHost: " + hostport + "\r\n\r\n")); err != nil {
		t.Fatalf("write connect: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("mapped 字面量已检地址不得被钉住复核拒掉（#123），实得 status=%d", resp.StatusCode)
	}
	body, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read tunneled data: %v", err)
	}
	if string(body) != "mapped-ok" {
		t.Fatalf("隧道数据失真：%q", body)
	}
}
