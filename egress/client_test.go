package egress

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestNewClientBlocksLoopbackDial(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	c := PublicOnly.MustClient(nil)
	resp, err := c.Get(srv.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("PublicOnly 应拦住回环拨号")
	}
	if _, ok := errors.AsType[*BlockedError](err); !ok {
		t.Fatalf("拒绝原因应是 *BlockedError，实际 %T：%v", err, err)
	}
	if hits != 0 {
		t.Fatalf("请求不应到达服务器（hits=%d）", hits)
	}
}

func TestNewClientPrivateNoLoopbackStillBlocksLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	c := PrivateNoLoopback.MustClient(nil)
	resp, err := c.Get(srv.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("PrivateNoLoopback 应拒回环")
	}
	if _, ok := errors.AsType[*BlockedError](err); !ok {
		t.Fatalf("拒绝原因应是 *BlockedError，实际 %T：%v", err, err)
	}
}

func TestNewClientSelfServiceAllowsLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	c := SelfService.MustClient(nil)
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("SelfService 应放行回环：%v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Fatalf("响应体不对：%q", body)
	}
}

func TestNewClientBlocksBeforeDialing(t *testing.T) {
	var mu sync.Mutex
	var dialed []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	base := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			mu.Lock()
			dialed = append(dialed, addr)
			mu.Unlock()
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}
	c := PublicOnly.MustClient(base)
	resp, err := c.Get(srv.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("应拦住回环")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(dialed) != 0 {
		t.Fatalf("判定应在拨号**之前**：被拒的地址不该被拨（dialed=%v）", dialed)
	}
}

func TestNewClientKeepsCustomDialer(t *testing.T) {
	var mu sync.Mutex
	var dialed []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	base := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			mu.Lock()
			dialed = append(dialed, addr)
			mu.Unlock()
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}
	c := SelfService.MustClient(base)
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("自服务应放行回环：%v", err)
	}
	_ = resp.Body.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(dialed) == 0 {
		t.Fatal("调用方自带的拨号器应被保留并使用")
	}
}

func TestNewClientGuardsRedirectTarget(t *testing.T) {
	var mu sync.Mutex
	var dialed []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data", http.StatusFound)
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("解析测试服务器地址失败：%v", err)
	}

	base := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			mu.Lock()
			dialed = append(dialed, addr)
			mu.Unlock()
			host, _, splitErr := net.SplitHostPort(addr)
			if splitErr == nil && host == "example.test" {
				// 把测试域名拨到本地测试服务器
				return (&net.Dialer{}).DialContext(ctx, network, u.Host)
			}
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}
	c := PublicOnly.MustClient(base)
	resp, err := c.Get("http://example.test/start")
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("重定向目标（云元数据地址）应被拨号层拦住")
	}
	if _, ok := errors.AsType[*BlockedError](err); !ok {
		t.Fatalf("拒绝原因应是 *BlockedError，实际 %T：%v", err, err)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, addr := range dialed {
		if strings.HasPrefix(addr, "169.254.169.254") {
			t.Fatalf("被拒的重定向目标不该被拨号（dialed=%v）", dialed)
		}
	}
}

func TestNewClientDoesNotMutateBaseOrDefault(t *testing.T) {
	base := &http.Client{Transport: &http.Transport{}}
	before := base.Transport
	c, err := PublicOnly.NewClient(base)
	if err != nil {
		t.Fatalf("NewClient 失败：%v", err)
	}
	if base.Transport != before {
		t.Fatal("调用方的传输器被改了")
	}
	if c.Transport == before {
		t.Fatal("应返回克隆的传输器，而不是复用调用方的")
	}

	def, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Fatal("默认传输器不是 *http.Transport")
	}
	defPtr := reflect.ValueOf(def.DialContext).Pointer()
	if http.DefaultClient.Transport != nil {
		t.Fatal("http.DefaultClient 的传输器被改了")
	}
	_ = SelfService.MustClient(nil)
	if reflect.ValueOf(def.DialContext).Pointer() != defPtr {
		t.Fatal("全局默认传输器被改了")
	}
	if http.DefaultClient.Transport != nil {
		t.Fatal("http.DefaultClient 的传输器被改了")
	}
}

func TestNewClientRejectsForeignRoundTripper(t *testing.T) {
	base := &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		return nil, errors.New("不该被调用")
	})}
	if _, err := PublicOnly.NewClient(base); err == nil {
		t.Fatal("非 *http.Transport 的传输器应报错")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("MustClient 应 panic")
		}
	}()
	PublicOnly.MustClient(base)
}

// TestNewClientGuardsLegacyDialTLS 回归（#74）：只设了废弃 DialTLS（未设
// DialTLSContext）的传输器，HTTPS 走 DialTLS——此前守卫只挂 DialContext，
// 这类传输器的 HTTPS 整路绕过拨号围栏。守卫必须先判后拨：被拒地址不得
// 触达调用方自带的 DialTLS。
func TestNewClientGuardsLegacyDialTLS(t *testing.T) {
	var mu sync.Mutex
	var dialed []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	base := srv.Client()
	tr := base.Transport.(*http.Transport)
	//nolint:staticcheck // SA1019：测试刻意只设废弃的 DialTLS 字段——钉住本条回归的场景
	tr.DialTLS = func(network, addr string) (net.Conn, error) {
		mu.Lock()
		dialed = append(dialed, addr)
		mu.Unlock()
		return dialTLSDial(srv, tr, network, addr)
	}
	c := PublicOnly.MustClient(base)
	resp, err := c.Get(srv.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("PublicOnly 应拦住回环的 HTTPS 拨号")
	}
	if _, ok := errors.AsType[*BlockedError](err); !ok {
		t.Fatalf("拒绝原因应是 *BlockedError，实际 %T：%v", err, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(dialed) != 0 {
		t.Fatalf("判定应在拨号之前：被拒地址不该触达 DialTLS（dialed=%v）", dialed)
	}
}

// TestNewClientKeepsLegacyDialTLS 放行面上，被守卫包住的废弃 DialTLS 仍要
// 真正被使用——守卫的语义是「先判后拨」，不是「丢弃调用方的拨号器」。
func TestNewClientKeepsLegacyDialTLS(t *testing.T) {
	var mu sync.Mutex
	hits := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	base := srv.Client()
	tr := base.Transport.(*http.Transport)
	//nolint:staticcheck // SA1019：同上，钉住「只设废弃 DialTLS」的输入形态
	tr.DialTLS = func(network, addr string) (net.Conn, error) {
		mu.Lock()
		hits++
		mu.Unlock()
		return dialTLSDial(srv, tr, network, addr)
	}
	c := SelfService.MustClient(base)
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("SelfService 应放行回环 HTTPS：%v", err)
	}
	_ = resp.Body.Close()
	mu.Lock()
	defer mu.Unlock()
	if hits == 0 {
		t.Fatal("放行时调用方自带的 DialTLS 应被保留并使用")
	}
}

// dialTLSDial 模拟一个真实的 DialTLS 实现：TCP 拨号后包 tls.Client 完成
// TLS 化（DialTLS 契约：返回的连接由调用方负责 TLS，net/http 不再补握手）。
func dialTLSDial(srv *httptest.Server, tr *http.Transport, network, addr string) (net.Conn, error) {
	raw, err := (&net.Dialer{}).Dial(network, addr)
	if err != nil {
		return nil, err
	}
	host, _, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		_ = raw.Close()
		return nil, splitErr
	}
	cfg := tr.TLSClientConfig.Clone()
	cfg.ServerName = host
	return tls.Client(raw, cfg), nil
}
