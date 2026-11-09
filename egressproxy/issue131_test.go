package egressproxy_test

import (
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oagentkit/guardx/egressproxy"
)

// 本文件钉 guardx#131 的回归：serveForward 不得静默改写请求 scheme——客户端
// 按 RFC 7230 绝对形态发 `GET https://host/... HTTP/1.1` 时，此前目标 scheme
// 被无条件覆盖成 http，代理按明文往 https 端口发整条请求（请求行 + 全部头，
// 含 Authorization/Cookie）。对端握手必败看似无害，但明文字节已经上线。
// https 目标必须改走 CONNECT 隧道，明文转发路径一律拒绝，不可降级。

// recordingTarget 裸 TCP 目标：记录收到的全部字节（并回一个最小 HTTP 响应，
// 供正向对照用例读到 200）。
func recordingTarget(t *testing.T) (addr string, port int, received func() []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听目标失败: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var mu sync.Mutex
	var buf []byte
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				b := make([]byte, 4096)
				for {
					n, rerr := c.Read(b)
					if n > 0 {
						mu.Lock()
						buf = append(buf, b[:n]...)
						mu.Unlock()
						_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
					}
					if rerr != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String(), ln.Addr().(*net.TCPAddr).Port, func() []byte {
		mu.Lock()
		defer mu.Unlock()
		return append([]byte(nil), buf...)
	}
}

// TestForwardRejectsAbsoluteFormHTTPS issue 复现：https 绝对形态被拒
// （400），目标收不到任何明文字节。
func TestForwardRejectsAbsoluteFormHTTPS(t *testing.T) {
	_, port, received := recordingTarget(t)
	proxy := startProxy(t, egressproxy.Policy{
		AllowHosts: []string{"127.0.0.1"},
		AllowPorts: []int{port},
	})
	conn, err := net.Dial("tcp", proxy.Host)
	if err != nil {
		t.Fatalf("连代理失败: %v", err)
	}
	defer func() { _ = conn.Close() }()
	req := "GET https://127.0.0.1:" + strconv.Itoa(port) + "/secret-path HTTP/1.1\r\n" +
		"Host: 127.0.0.1:" + strconv.Itoa(port) + "\r\n" +
		"X-Secret-Header: topsecret\r\n" +
		"Connection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("写请求失败: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	b := make([]byte, 4096)
	n, _ := conn.Read(b)
	resp := string(b[:n])
	if !strings.Contains(resp, "400") {
		t.Fatalf("https 绝对形态应被 400 拒绝（不得静默降级 http）: %q", resp)
	}
	if strings.Contains(resp, "200") {
		t.Fatalf("https 明文转发被放行: %q", resp)
	}
	// 明文字节不得上线：给目标留出接收窗口后核对
	time.Sleep(200 * time.Millisecond)
	if got := received(); len(got) != 0 {
		t.Fatalf("明文字节已上线——目标收到了: %q", got)
	}
}

// TestForwardStillServesPlainHTTP 正向对照：http 绝对形态照常转发（拒绝
// 只收窄到非 http scheme，不伤明文代理主通道）。
func TestForwardStillServesPlainHTTP(t *testing.T) {
	addr, port, received := recordingTarget(t)
	proxy := startProxy(t, egressproxy.Policy{
		AllowHosts: []string{"127.0.0.1"},
		AllowPorts: []int{port},
	})
	conn, err := net.Dial("tcp", proxy.Host)
	if err != nil {
		t.Fatalf("连代理失败: %v", err)
	}
	defer func() { _ = conn.Close() }()
	req := "GET http://" + addr + "/ok-path HTTP/1.1\r\n" +
		"Host: " + addr + "\r\n" +
		"Connection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("写请求失败: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	b := make([]byte, 4096)
	n, _ := conn.Read(b)
	resp := string(b[:n])
	if !strings.Contains(resp, "200") {
		t.Fatalf("http 绝对形态应照常转发: %q", resp)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := received(); strings.Contains(string(got), "ok-path") {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("目标应收到转发的请求: %q", received())
}

// TestForwardOriginFormUntouched origin-form（无 scheme）请求不受影响：
// scheme 准入只拦「明确声明了非 http scheme」的请求。
func TestForwardOriginFormUntouched(t *testing.T) {
	origin := startProxy(t, egressproxy.Policy{AllowHosts: []string{"127.0.0.1"}})
	// 借 proxy 自身当目标没有意义——用标准 client 走 origin-form 打到
	// httptest 语义外无法落地的地址会 502；这里只验证 scheme 检查不拦
	// 空 scheme：直接构造 origin-form 请求打到回环上已关闭的端口，
	// 期望走到「上游请求失败 502」而非 400。
	conn, err := net.Dial("tcp", origin.Host)
	if err != nil {
		t.Fatalf("连代理失败: %v", err)
	}
	defer func() { _ = conn.Close() }()
	req := "GET /some-path HTTP/1.1\r\nHost: 127.0.0.1:1\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("写请求失败: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	b := make([]byte, 4096)
	n, _ := conn.Read(b)
	resp := string(b[:n])
	if strings.Contains(resp, "400 ") {
		t.Fatalf("origin-form（空 scheme）不得被 scheme 准入拦下: %q", resp)
	}
}
