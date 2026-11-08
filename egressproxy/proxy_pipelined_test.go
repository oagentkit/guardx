package egressproxy_test

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/oagentkit/guardx/egressproxy"
)

// 本文件钉 guardx#99 的回归：CONNECT 隧道不得丢弃 hijack 时已缓冲在
// bufio.Reader 里的字节。net/http 的 Hijack 契约写明 bufrw.Reader 可能持有
// 未处理字节——客户端把 CONNECT 请求头与早期数据（如紧随其后的 TLS
// ClientHello）写在同一个 TCP 段里时，那段字节落在 bufio 缓冲里；
// pump 只读裸连接，缓冲里的字节被静默吞掉，隧道就此停摆。

// TestConnectTunnelPipelinedEarlyData 一次写出发出 CONNECT 头 + 早期数据：
// 早期数据必须经隧道抵达目标并被带回，隧道继续双向可用。
func TestConnectTunnelPipelinedEarlyData(t *testing.T) {
	// 目标侧：裸 TCP 回声服务（真实目标通常是 TLS，隧道字节面等价）。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		buf := make([]byte, 4096)
		for {
			n, rerr := c.Read(buf)
			if n > 0 {
				if _, werr := c.Write(buf[:n]); werr != nil {
					return
				}
			}
			if rerr != nil {
				return
			}
		}
	}()

	proxy := startProxy(t, egressproxy.Policy{
		AllowHosts: []string{"127.0.0.1"},
		AllowPorts: []int{port},
	})

	conn, err := net.Dial("tcp", proxy.Host)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	early := "EARLY-HELLO-1234"
	// 一次写：CONNECT 请求头 + 管道化早期数据（同一 TCP 段——被 hijack 的
	// bufio.Reader 缓冲的正是这段）。HTTP/1.1 的 CONNECT 带 Host 头。
	hostport := "127.0.0.1:" + strconv.Itoa(port)
	req := "CONNECT " + hostport + " HTTP/1.1\r\nHost: " + hostport + "\r\n\r\n" + early
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write connect+early: %v", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read 200: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Status, "200") {
		t.Fatalf("应先收到 200 响应，实得 %q", resp.Status)
	}

	// 早期数据必须经隧道抵达目标并被回声带回（修前：缓冲字节被吞，隧道停摆）。
	got := make([]byte, len(early))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("管道化早期数据丢失（#99）: %v", err)
	}
	if string(got) != early {
		t.Fatalf("早期数据被破坏: got %q want %q", got, early)
	}

	// 隧道继续可用：后续字节双向照常。
	second := "SECOND-CHUNK-5678"
	if _, err := conn.Write([]byte(second)); err != nil {
		t.Fatalf("write second: %v", err)
	}
	got2 := make([]byte, len(second))
	if _, err := io.ReadFull(br, got2); err != nil {
		t.Fatalf("隧道后续字节丢失: %v", err)
	}
	if string(got2) != second {
		t.Fatalf("隧道后续字节被破坏: got %q want %q", got2, second)
	}
}
