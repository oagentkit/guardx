package egress

import (
	"context"
	"net"
	"net/http"

	"github.com/oekit/pkg/errors"
)

// NewClient 派生一个把**同一放行面**落到拨号层的 *http.Client。
//
// # 拨号层判的是什么
//
// 拨号层用的是与写面**同一个字面量判定**（Policy.CheckHost）：拨号地址的 host
// 是 IP 字面量时按放行面判；是域名时放行——与本包「只做字面量判定、不做 DNS
// preflight」的既有口径一致。
//
// 刻意**不做**「连上之后核对实际对端地址」：那会让拨号层比写面**更严**
// （写面放行域名、拨号层拒它的解析结果），两层口径就又不一致了——
// 那正是本类型要消灭的故障形态。解析层防护仍由消费方按需叠加。
//
// # 拨号层多出来的价值
//
//   - **重定向**：http.Client 默认跟随重定向，而写面只校验了**最初那个 URL**；
//     真正被拨号的是重定向目标 ⇒ 由拨号层兜住。
//   - **漏掉写面校验的调用方**：拨号层仍然拦住 IP 字面量目标。
//
// # 边界（有意不覆盖的）
//
//   - 走了代理（Transport.Proxy）时，拨号地址是**代理地址**而不是目标地址 ⇒
//     目标侧的判定仍要靠写面 p.Check(url)。
//   - 域名解析到私网（DNS 层）不在本包判定面内——与包的既有口径一致。
//
// # 参数与错误
//
// base 为 nil 时按 http.DefaultClient 取；**不修改** base，也不修改全局默认传输器
// （默认传输器走 Clone）。base.Transport 不是 *http.Transport 时挂不上拨号守卫 ⇒
// 返回错误（用 MustClient 则 panic）。
func (p Policy) NewClient(base *http.Client) (*http.Client, error) {
	if base == nil {
		base = http.DefaultClient
	}
	tr := base.Transport
	if tr == nil {
		tr = http.DefaultTransport
	}
	ht, ok := tr.(*http.Transport)
	if !ok {
		return nil, errors.Errorf("egress: 传输器 %T 不是 *http.Transport，挂不上拨号守卫", tr)
	}
	// Clone：不改调用方的传输器，也不改全局默认传输器。
	clone := ht.Clone()
	origDialCtx := clone.DialContext
	//nolint:staticcheck // SA1019：Dial 虽已废弃，但仍要读它——DialContext 为 nil 而 Dial 非 nil 时，
	// net/http 会走 Dial；不读就会静默丢弃调用方自带的拨号器（改走默认拨号器）。
	origDial := clone.Dial
	origTLS := clone.DialTLSContext
	clone.DialContext = p.guardDial(origDialCtx, origDial)
	clone.DialTLSContext = p.guardDialTLS(origTLS)
	out := *base
	out.Transport = clone
	return &out, nil
}

// MustClient 同 NewClient，出错即 panic（适合包级初始化等不容错的场景）。
func (p Policy) MustClient(base *http.Client) *http.Client {
	c, err := p.NewClient(base)
	if err != nil {
		panic(err)
	}
	return c
}

// guardDial 产出「先判后拨」的拨号函数。
//
// inner 的取法与 net/http 传输器的缺省拨号顺序一致：优先 DialContext，其次旧的
// Dial，都没有时用零值 net.Dialer（与 net/http 内部 zeroDialer 同形）。
func (p Policy) guardDial(
	dialCtx func(context.Context, string, string) (net.Conn, error),
	dial func(string, string) (net.Conn, error),
) func(context.Context, string, string) (net.Conn, error) {
	inner := dialCtx
	switch {
	case inner != nil:
		// 调用方自带拨号器：原样保留，只在外面加判定。
	case dial != nil:
		// 旧的已废弃 Dial 字段（无 ctx）：包一层成 DialContext 形态。
		inner = func(_ context.Context, network, addr string) (net.Conn, error) {
			return dial(network, addr)
		}
	default:
		var zeroDialer net.Dialer
		inner = zeroDialer.DialContext
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		// 判定在拨号**之前**：被拒的地址不会被连上。
		if err := p.checkDialAddr(addr); err != nil {
			return nil, err
		}
		return inner(ctx, network, addr)
	}
}

// guardDialTLS 同样给 TLS 拨号加判定——否则自定义了 DialTLSContext 的传输器
// 会绕开拨号守卫（那是覆盖面上的洞，不是语义分歧）。
func (p Policy) guardDialTLS(
	tls func(context.Context, string, string) (net.Conn, error),
) func(context.Context, string, string) (net.Conn, error) {
	if tls == nil {
		return nil
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if err := p.checkDialAddr(addr); err != nil {
			return nil, err
		}
		return tls(ctx, network, addr)
	}
}

// checkDialAddr 按放行面判定拨号地址（host:port 形态），用的是与写面同一个
// 字面量判定（Policy.CheckHost）。
func (p Policy) checkDialAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// 不是 host:port 形态（缺端口 / IPv6 无括号）：按整体当 host 判，
		// 判不出来的形态交给 CheckHost fail-closed。
		host = addr
	}
	return p.CheckHost(host)
}
