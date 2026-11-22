// client.go —— 出站守卫的**接线件**：把拨号层守卫挂到宿主的 HTTP 客户端上。
//
// # 为什么需要它（issue #6）
//
// 拨号层守卫要生效，宿主必须把 `Transport.DialContext` 换成 `netguard.DialFunc`。
// 这一步在宿主侧散落着，且有两个反复出现的坑：
//
//  1. **client 写死在业务代码里，测试无法注入**——宿主有 `&http.Client{Timeout: ...}`
//     的写法，测试连不上自己的假服务器（httptest 跑在 127.0.0.1，而守卫按缺省
//     放行面拒回环）。于是要么测试被守卫挡住，要么有人把生产配置一起放宽——
//     **后者等于把刚补上的窗口重新打开**。
//  2. **两层口径容易不一致**——校验层与拨号层各写一份开关，值传岔了就成了
//     「分层放行」。
//
// 本文件把这两件事收口：
//
//   - 守卫挂在**传输层**（拨号发生的地方），宿主已有 client/transport 可整体注入；
//   - 放行面用**同一个类型**（Allow，见 allow.go），两层不可能各持一套开关。
//
// # 用法
//
// 生产：
//
//	hc, err := netguard.NewClient(nil, netguard.Allow{})   // 零值 = 私网与回环全拒
//
// 测试（要连回环上的假服务器时，**只在测试里放宽**回环）：
//
//	hc, err := netguard.NewClient(&http.Client{Timeout: 2 * time.Second},
//	                             netguard.Allow{Loopback: true})
//
// 生产路径不放宽——放宽不是「配置」，是把出站防线重新打开。

package netguard

import (
	"context"
	"fmt"
	"net"
	"net/http"
)

// NewTransport 返回一个挂了出站守卫拨号器的传输层。
//
// # 代理与守卫互斥（issue #211）
//
// Go 传输层配置了代理时，DialContext 收到的是**代理**的 host:port（CONNECT /
// 绝对 URI 的目标由代理解析）——守卫的三道判据（名字层 / 解析后预检 /
// 建连后核对 RemoteAddr）会全部落在代理上，真实目标一道都不过。「守卫看起来
// 接上了，实际没接」正是本包拒绝的失败形态，因此：
//
//   - base 显式配了 Proxy（base.Proxy != nil）⇒ **构造报错**，与 NewClient
//     对自定义 RoundTripper 同一条纪律：拨号层无法校验真实目标时宁可不接，
//     而不是接一个假的。宿主若必须经代理出站，出站校验要移到代理侧实现；
//   - base 为 nil（克隆 http.DefaultTransport，自带环境代理
//     ProxyFromEnvironment）⇒ 克隆后**剥掉环境代理**：守卫传输层一律直连
//     目标，HTTP_PROXY/HTTPS_PROXY 等环境变量对它不生效。只会经代理出网的
//     宿主会在请求期得到拨号错误（fail-closed）——那是响亮的「这条路走不通」，
//     不是绕过守卫的「静默放行」。
//
// base 为 nil 时克隆 http.DefaultTransport。base 自己的 DialContext 会被守卫
// **包住**（守卫叠加在它之上，不是替换它）——宿主已有的自定义拨号器与
// 连接池参数不会丢。
//
// base 只设了废弃字段 Dial（未设 DialContext）时同样成立：旧拨号器被适配成
// DialFunc 的 next 交给守卫包住（issue #152）。此前这里只包装 DialContext，
// 只设 Dial 的宿主自定义拨号器被静默丢弃——克隆后 DialContext 为 nil，
// DialFunc(nil,…) 落缺省拨号器，而 net/http 的 DialContext 优先语义使旧 Dial
// 被完全忽略，连接行为静默改变。适配丢掉的只有 ctx：废弃 API 本身不接收
// context（请求取消/期限不再传导到拨号器，这是 http.Transport.Dial 的既有
// 局限，不是本包装引入的）。
//
// 守卫只能挂在传输层：拨号发生在传输层内部，绕开传输层就没有拨号层防线。
func NewTransport(base *http.Transport, allow Allow) (*http.Transport, error) {
	if base != nil && base.Proxy != nil {
		return nil, fmt.Errorf(
			"传输层配了代理（Proxy != nil）：拨号层只会看到代理地址，守卫判据全部落在代理上、" +
				"真实目标一道判据都不过——挂拨号层守卫等于没挂。请去掉代理直连（环境代理对守卫" +
				"传输层本就不生效），或把出站校验移到代理侧实现")
	}
	var t *http.Transport
	if base == nil {
		t = http.DefaultTransport.(*http.Transport).Clone()
		t.Proxy = nil // issue #211：环境代理会让守卫只校验代理地址——守卫传输层一律直连真实目标
	} else {
		t = base.Clone()
	}
	if t.DialContext == nil && t.Dial != nil { //nolint:staticcheck // 适配废弃字段正是本分支的职责：宿主只设了 Dial，读它是修 #152 的前提
		// 只设 Dial 的 base：把旧拨号器适配成 next（issue #152）——
		// 守卫包住它，而不是用缺省拨号器把它替换掉。
		next := t.Dial //nolint:staticcheck // 同上：读宿主设置的废弃字段再包进守卫
		t.DialContext = DialFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
			return next(network, addr)
		}, DialOptions{Allow: allow})
		t.Dial = nil //nolint:staticcheck // 清掉死字段：DialContext 已设，net/http 会忽略 Dial
		return t, nil
	}
	t.DialContext = DialFunc(t.DialContext, DialOptions{Allow: allow})
	return t, nil
}

// NewClient 返回一个挂了出站守卫的 HTTP 客户端。
//
// base 为 nil 时用 http.DefaultClient 的形状（零值 client）。base 的其余字段
// （Timeout / Jar / CheckRedirect）原样保留。
//
// base.Transport 若是 *http.Transport 则克隆并挂上守卫；若是自定义 RoundTripper
// 则**无法**挂拨号层守卫（拨号发生在传输层内部），此时返回错误——而不是悄悄
// 放行。「悄悄放行」的失败形态是「守卫看起来接上了，实际没接」。base 的
// 传输层若显式配了代理，同样报错（见 NewTransport：代理形态下守卫判据全部
// 落在代理上，issue #211）。
//
// base.Transport 为 nil 时用 http.DefaultTransport 的克隆（剥掉环境代理——
// 守卫传输层一律直连）。
func NewClient(base *http.Client, allow Allow) (*http.Client, error) {
	c := &http.Client{}
	if base != nil {
		// http.Client 无锁，浅拷贝安全；Transport 随后被替换成克隆，base 不受影响。
		cc := *base
		c = &cc
	}
	var err error
	switch tr := c.Transport.(type) {
	case nil:
		c.Transport, err = NewTransport(nil, allow)
	case *http.Transport:
		c.Transport, err = NewTransport(tr, allow)
	default:
		return nil, fmt.Errorf(
			"客户端的 Transport 是自定义 RoundTripper（%T），无法挂拨号层守卫：拨号发生在传输层内部；"+
				"请改用 *http.Transport，或在传输层之外另设出站闸", tr)
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}
