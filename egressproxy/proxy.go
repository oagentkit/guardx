package egressproxy

import (
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oagentkit/guardx/sandbox"
	"github.com/oekit/pkg/errors"
)

// dialTimeout 连接目标的期限。够长以覆盖跨境 RTT，够短以不把一次挂起的
// 目标拖成整条工具调用的超时。
const dialTimeout = 10 * time.Second

// Proxy 本地出口代理（HTTP 转发 + CONNECT 隧道）。
//
// 零值不可用：必须 `New` → `Start`。`Close` 幂等。
type Proxy struct {
	policy    Policy
	ln        net.Listener
	srv       *http.Server
	transport *http.Transport
	dialer    *net.Dialer
}

// New 构造代理（**不启动**）。放行面非法即报错——不带着半份策略开始服务。
func New(p Policy) (*Proxy, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	d := &net.Dialer{Timeout: dialTimeout}
	return &Proxy{
		policy: p,
		dialer: d,
		transport: &http.Transport{
			// 自己绝不再经过一个代理：配置文件里的 HTTP_PROXY 会让它把请求
			// 转给另一个代理，形成自环或把流量交给不受控的第三方。
			Proxy:             nil,
			DialContext:       d.DialContext,
			DisableKeepAlives: true,
		},
	}, nil
}

// Start 在回环上监听并开始服务，返回可直接用于环境变量的代理地址
// （形如 `http://127.0.0.1:3128`）。
//
// **只监听 127.0.0.1**：它是要塞的墙，不是要对外开放的服务。
func (p *Proxy) Start() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", errors.Wrap(err, "egressproxy: 监听回环地址失败")
	}
	p.ln = ln
	p.srv = &http.Server{Handler: p, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = p.srv.Serve(ln) }()
	return "http://" + ln.Addr().String(), nil
}

// Addr 返回监听地址（未启动时为空）。
func (p *Proxy) Addr() string {
	if p.ln == nil {
		return ""
	}
	return p.ln.Addr().String()
}

// Close 停止服务并释放连接（幂等）。
func (p *Proxy) Close() error {
	if p.srv == nil {
		return nil
	}
	err := p.srv.Close()
	p.transport.CloseIdleConnections()
	return err
}

// Egress 实现 sandbox.EgressEnforcer：本代理能兑现的是 `proxy` 档。
//
// **不声称 `denied`**：代理挡得住「经过它的流量」，挡不住绕开代理的原始
// socket —— 声称禁网就是让档位表说谎。
func (p *Proxy) Egress() sandbox.EgressMode { return sandbox.EgressProxy }

// ServeHTTP 实现 http.Handler（代理形态）。
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.serveConnect(w, r)
		return
	}
	p.serveForward(w, r)
}

// serveConnect 处理 `CONNECT host:port`：先准入，再建隧道，之后只搬字节。
func (p *Proxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	host, port, err := splitHostPort(r.Host, 443)
	if err != nil {
		p.reject(w, &BlockedError{Host: r.Host, Reason: err.Error()})
		return
	}
	// CONNECT 的方法恒为 CONNECT，Limited 在这里无法区分读写——见 Policy.Limited 的边界说明。
	if err := p.policy.Permit(host, port); err != nil {
		p.reject(w, err)
		return
	}
	target, err := p.dialer.DialContext(r.Context(), "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		http.Error(w, "egressproxy: 连接目标失败: "+err.Error(), http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = target.Close()
		http.Error(w, "egressproxy: 当前连接不支持隧道", http.StatusInternalServerError)
		return
	}
	client, bufrw, err := hj.Hijack()
	if err != nil {
		_ = target.Close()
		return
	}
	if _, err := bufrw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = client.Close()
		_ = target.Close()
		return
	}
	if err := bufrw.Flush(); err != nil {
		_ = client.Close()
		_ = target.Close()
		return
	}
	pump(client, target)
}

// serveForward 处理明文 HTTP 代理请求（绝对 URI 形态）。
func (p *Proxy) serveForward(w http.ResponseWriter, r *http.Request) {
	host, port, err := requestTarget(r)
	if err != nil {
		p.reject(w, &BlockedError{Host: r.Host, Reason: err.Error()})
		return
	}
	if p.policy.Limited && r.Method != http.MethodGet && r.Method != http.MethodHead {
		p.reject(w, &BlockedError{Host: host, Port: port, Reason: "只读模式下只允许 GET/HEAD，收到 " + r.Method})
		return
	}
	if err := p.policy.Permit(host, port); err != nil {
		p.reject(w, err)
		return
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.URL.Scheme = "http"
	out.URL.Host = net.JoinHostPort(host, strconv.Itoa(port))
	stripHopByHop(out.Header)

	resp, err := p.transport.RoundTrip(out)
	if err != nil {
		http.Error(w, "egressproxy: 上游请求失败: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	stripHopByHop(resp.Header)
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// reject 统一拒绝形态：403 + 结构化原因（响应头带上原因，便于调用方区分
// 「被墙拒」与「目标自己返回 403」）。
func (p *Proxy) reject(w http.ResponseWriter, err error) {
	var be *BlockedError
	if errors.As(err, &be) {
		w.Header().Set("X-Egress-Blocked", be.Reason)
		http.Error(w, be.Error(), http.StatusForbidden)
		return
	}
	http.Error(w, err.Error(), http.StatusBadRequest)
}

// requestTarget 从明文代理请求里取目标主机与端口。
func requestTarget(r *http.Request) (string, int, error) {
	hostport := r.URL.Host
	if hostport == "" {
		hostport = r.Host
	}
	if hostport == "" {
		return "", 0, errors.New("请求里没有目标主机")
	}
	return splitHostPort(hostport, 80)
}

// splitHostPort 解析 host[:port]；缺端口用 dflt。
func splitHostPort(hostport string, dflt int) (string, int, error) {
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		n, cerr := strconv.Atoi(p)
		if cerr != nil || n < 1 || n > 65535 {
			return "", 0, errors.Errorf("端口 %q 非法", p)
		}
		return h, n, nil
	}
	h := strings.Trim(hostport, "[]")
	if h == "" {
		return "", 0, errors.New("目标主机为空")
	}
	return h, dflt, nil
}

// pump 双向搬运（一侧用当前 goroutine，另一侧一条 goroutine），两侧都关半写。
func pump(client, target net.Conn) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(target, client)
		closeWrite(target)
	}()
	_, _ = io.Copy(client, target)
	closeWrite(client)
	wg.Wait()
	_ = client.Close()
	_ = target.Close()
}

type closeWriter interface{ CloseWrite() error }

func closeWrite(c net.Conn) {
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

// hopByHop 逐跳头：代理不得转发。
var hopByHop = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func stripHopByHop(h http.Header) {
	for _, k := range hopByHop {
		h.Del(k)
	}
}

func copyHeader(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}
