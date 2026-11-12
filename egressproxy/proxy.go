package egressproxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"fmt"
	"github.com/oagentkit/guardx/sandbox"

	"github.com/oekit/pkg/errors"
)

// dialTimeout 连接目标的期限。够长以覆盖跨境 RTT，够短以不把一次挂起的
// 目标拖成整条工具调用的超时。
const dialTimeout = 10 * time.Second

// pinnedAddrsKey 请求上下文里「这条请求的已检地址」（guardx#96）：写面
// PermitResolving 解析并全量过 IP 围栏后放进请求 ctx，拨号面取出来钉住
// ——拨号只连已检地址，不再二次解析。
type pinnedAddrsKey struct{}

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
	tr := &http.Transport{
		// 自己绝不再经过一个代理：配置文件里的 HTTP_PROXY 会让它把请求
		// 转给另一个代理，形成自环或把流量交给不受控的第三方。
		Proxy:             nil,
		DialContext:       d.DialContext,
		DisableKeepAlives: true,
	}
	// 拨号面钉住（guardx#96）：请求 ctx 里带已检地址时只连它们（字面量
	// 直连 + Control 复核，闭合 check/use 间 TOCTOU）；没有已检地址
	// （SkipDNSCheck / 旧形态）回落按主机名拨号。端口读不出来按
	// fail-closed 报错——已检地址是对请求端口过检的，拨别的端口没有依据。
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addrs, ok := ctx.Value(pinnedAddrsKey{}).([]netip.Addr); ok && len(addrs) > 0 {
			_, portStr, perr := net.SplitHostPort(addr)
			if perr != nil {
				return nil, fmt.Errorf("egressproxy: 已钉拨号地址 %q 不是 host:port 形态", addr)
			}
			portNum, aerr := strconv.Atoi(portStr)
			if aerr != nil || portNum < 1 || portNum > 65535 {
				return nil, fmt.Errorf("egressproxy: 已钉拨号端口 %q 非法", portStr)
			}
			return pinnedDial(d, ctx, addrs, portNum)
		}
		return d.DialContext(ctx, network, addr)
	}
	return &Proxy{
		policy:    p,
		dialer:    d,
		transport: tr,
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

// serveConnect 处理 `CONNECT host:port`：先准入（含 DNS 围栏），按已检
// 地址拨号建隧道，之后只搬字节。
func (p *Proxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	host, port, err := splitHostPort(r.Host, 443)
	if err != nil {
		p.reject(w, &BlockedError{Host: r.Host, Reason: err.Error()})
		return
	}
	// CONNECT 的方法恒为 CONNECT，Limited 在这里无法区分读写——见 Policy.Limited 的边界说明。
	addrs, err := p.policy.PermitResolving(r.Context(), host, port)
	if err != nil {
		p.reject(w, err)
		return
	}
	target, err := p.dialTarget(r.Context(), host, addrs, port)
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
	// #99：hijack 时 bufrw.Reader 里可能已缓冲了客户端在同一 TCP 段里
	// pipeline 过来的早期数据（如紧随 CONNECT 的 TLS ClientHello）——
	// net/http 的 Hijack 契约写明 Reader 可能持有未处理字节。pump 只读
	// 裸连接、不再经过 bufrw，这些字节若不先灌进隧道就被静默吞掉（隧道
	// 停摆：目标等不到 ClientHello，客户端等不到 ServerHello）。先排空
	// 缓冲，再开始双向拷贝。
	if n := bufrw.Reader.Buffered(); n > 0 {
		buf := make([]byte, n)
		if _, err := io.ReadFull(bufrw.Reader, buf); err != nil {
			_ = client.Close()
			_ = target.Close()
			return
		}
		if _, err := target.Write(buf); err != nil {
			_ = client.Close()
			_ = target.Close()
			return
		}
	}
	pump(client, target)
}

// serveForward 处理明文 HTTP 代理请求（绝对 URI 形态）。
func (p *Proxy) serveForward(w http.ResponseWriter, r *http.Request) {
	// scheme 准入（guardx#131）：本路径只服务明文转发。客户端按 RFC 7230
	// 绝对形态发 `GET https://host/... HTTP/1.1` 时，此前目标 scheme 被
	// 无条件覆盖成 http——代理按明文把整条请求（请求行 + 全部头，含
	// Authorization/Cookie）发往 https 端口。对端是 TLS 故握手必败（客户端
	// 拿 502），看似无害，但明文字节已经上线：放行名单内的任何链路观测者
	// 都读得到。既不是 CONNECT 路径也不在 DNS 围栏射程内——不可静默改写
	// scheme，非 http 目标一律拒绝（应改走 CONNECT 隧道）；origin-form
	//（空 scheme）不受影响。
	if sch := r.URL.Scheme; sch != "" && sch != "http" {
		http.Error(w, "egressproxy: 明文转发不支持 "+sch+" 目标——请改走 CONNECT 隧道", http.StatusBadRequest)
		return
	}
	host, port, err := requestTarget(r)
	if err != nil {
		p.reject(w, &BlockedError{Host: r.Host, Reason: err.Error()})
		return
	}
	if p.policy.Limited && r.Method != http.MethodGet && r.Method != http.MethodHead {
		p.reject(w, &BlockedError{Host: host, Port: port, Reason: "只读模式下只允许 GET/HEAD，收到 " + r.Method})
		return
	}
	addrs, err := p.policy.PermitResolving(r.Context(), host, port)
	if err != nil {
		p.reject(w, err)
		return
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.URL.Scheme = "http"
	out.URL.Host = net.JoinHostPort(host, strconv.Itoa(port))
	stripHopByHop(out.Header)
	// 已检地址放进请求 ctx：transport 的 DialContext 取出来钉住拨号
	// （guardx#96——写面检查的地址集与拨号面连接的地址集同源）。
	if len(addrs) > 0 {
		out = out.WithContext(context.WithValue(out.Context(), pinnedAddrsKey{}, addrs))
	}

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

// dialTarget 连接目标：有已检地址时只连它们（guardx#96 拨号钉住）；没有
// （SkipDNSCheck / 字面量围栏关闭的旧形态）按主机名拨号。
func (p *Proxy) dialTarget(ctx context.Context, host string, addrs []netip.Addr, port int) (net.Conn, error) {
	if len(addrs) == 0 {
		return p.dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	}
	return pinnedDial(p.dialer, ctx, addrs, port)
}

// pinnedDial 逐个已检地址字面量直连（guardx#96 拨号钉住）——不再二次解析，
// 闭合「检查后换解析」的 TOCTOU；并挂 Control 复核实际拨号地址必须属于
// 已检集合（纵深：哪怕拨号路径将来多出回退分支，逃不出这份集合）。
//
// 集合键、拨号字面量、Control 比对三方统一 Unmap().String()（guardx#123）：
// Control 从 net 栈收到的是点分 v4 形态（v4 地址没有 mapped 形态），集合键
// 若建在 ::ffff: 前缀形态上则恒不相等——钉住复核把合法已检地址全拒。生产侧
// （PermitResolving）已归一，这里再归一是纵深：任何将来多出的地址来源都不
// 能靠形态差异逃过或误触复核。
func pinnedDial(d *net.Dialer, ctx context.Context, addrs []netip.Addr, port int) (net.Conn, error) {
	allowed := make(map[string]struct{}, len(addrs))
	for _, a := range addrs {
		allowed[a.Unmap().String()] = struct{}{}
	}
	pin := *d
	pin.Control = func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("egressproxy: 已钉拨号地址 %q 不是 host:port 形态", address)
		}
		got, err := netip.ParseAddr(host)
		if err != nil {
			return fmt.Errorf("egressproxy: 已钉拨号地址 %q 不是 IP 字面量", address)
		}
		if _, ok := allowed[got.Unmap().String()]; !ok {
			return &BlockedError{Host: host, Port: port, Reason: "拨号地址 " + got.String() + " 不在已检地址集合内（TOCTOU 钉住）"}
		}
		return nil
	}
	var lastErr error
	for _, a := range addrs {
		c, err := pin.DialContext(ctx, "tcp", net.JoinHostPort(a.Unmap().String(), strconv.Itoa(port)))
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("egressproxy: 没有可拨的已检地址")
	}
	return nil, lastErr
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
			return "", 0, fmt.Errorf("端口 %q 非法", p)
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
	wg.Go(func() {
		_, _ = io.Copy(target, client)
		closeWrite(target)
	})
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
