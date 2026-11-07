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
	origTLSCtx := clone.DialTLSContext
	//nolint:staticcheck // SA1019：DialTLS 同为废弃字段，同样要读——DialTLSContext 为 nil 而
	// DialTLS 非 nil 时，net/http 对 HTTPS 走 DialTLS；不读它，HTTPS 整路绕过拨号守卫。
	origTLS := clone.DialTLS
	clone.DialContext = p.guardDial(origDialCtx, origDial)
	clone.DialTLSContext = p.guardDialTLS(origTLSCtx, origTLS)
	// 守卫已包进 DialTLSContext（net/http 优先取它），废弃字段清零——
	// 留着只会给「这条传输器到底走没走守卫」留下一个永远读不到的岔路。
	//nolint:staticcheck // SA1019：清零同样是「使用」废弃字段，理由与上面的读取一致
	clone.Dial = nil
	//nolint:staticcheck // SA1019：同上
	clone.DialTLS = nil
	out := *base
	out.Transport = clone
	return &out, nil
}

// maxRedirects 重定向跳数上限（与 net/http 的默认口径一致：`len(via) >= 10` 即拒，
// via 装的是**已经发出**的请求，故最多跟随 10 跳）。
const maxRedirects = 10

// CheckRedirect 逐跳判定，直接赋给 http.Client.CheckRedirect。
//
// # 它补的是哪一半
//
// 写面（Check / CheckWith）只判**首跳 URL**；NewClient 的拨号层守卫兜住了重定向
// 目标，但它有两个结构性盲点：
//
//   - **调用方自带的传输器不是 *http.Transport**（otelhttp / 重试 / 认证包装都是
//     RoundTripper 包装）⇒ NewClient 直接返回错误，调用方在本包内没有任何逐跳路径；
//   - **走代理**（Transport.Proxy）时拨号地址是**代理地址** ⇒ 拨号层看不到目标。
//     这正是 NewClient 注释里写明的边界（「走了代理时目标侧判定仍要靠写面」），
//     而重定向时**写面只判了首跳**——于是这一段是裸的。
//
// # 跳数上限为什么必须在这里承担
//
// `http.Client` 一旦设置了 CheckRedirect，**就不再套用自己的默认 10 跳上限**。所以
// 一个「只判 URL 不判跳数」的 CheckRedirect 等于顺手把默认的跳数保护关掉——
// 上限必须在同一个函数里。这里固定取 net/http 的默认值 10；要换上限就自己包一层
// （先判 `len(via)` 再调本函数），本包**不另开一个上限旋钮**：两个上限并存时谁
// 生效取决于调用点，口径必然漂。
//
// # 用法
//
//	c := p.MustClient(base)                 // 拨号层守卫（非代理场景已足够）
//	c.CheckRedirect = p.CheckRedirect       // 代理场景 / 自定义传输器的逐跳兜底
//
// 两者同时挂是**纵深**，不是二选一：一次重定向会先过 CheckRedirect，真正拨号时再过
// 拨号层守卫——两层判的是同一份放行面，故不会出现「一层放行、一层拒」的假红。
func (p Policy) CheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return errors.Errorf("egress: 重定向超过 %d 跳（停在 %s）", maxRedirects, req.URL.Redacted())
	}
	return checkURLWith(req.URL, p)
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

// guardDialTLS 同样给 TLS 拨号加判定——否则自定义了 DialTLSContext（或废弃的
// DialTLS）的传输器会绕开拨号守卫（那是覆盖面上的洞，不是语义分歧）。
//
// tlsCtx 与 tls 都为 nil 时返回 nil（交回 net/http 的缺省拨号路径，该路径
// 已由 DialContext 上的守卫覆盖）。tlsCtx 为 nil 而 tls 非 nil 时把废弃的
// 无 ctx 形态包一层，与 guardDial 对待废弃 Dial 的方式对称。
func (p Policy) guardDialTLS(
	tlsCtx func(context.Context, string, string) (net.Conn, error),
	tls func(string, string) (net.Conn, error),
) func(context.Context, string, string) (net.Conn, error) {
	inner := tlsCtx
	switch {
	case inner != nil:
		// 调用方自带 TLS 拨号器：原样保留，只在外面加判定。
	case tls != nil:
		// 废弃的 DialTLS 字段（无 ctx）：包一层成 DialTLSContext 形态。
		inner = func(_ context.Context, network, addr string) (net.Conn, error) {
			return tls(network, addr)
		}
	default:
		return nil
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if err := p.checkDialAddr(addr); err != nil {
			return nil, err
		}
		return inner(ctx, network, addr)
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
