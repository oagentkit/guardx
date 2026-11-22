package netguard

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/oekit/pkg/errors"
)

// errResolver 恒定解析失败的测试解析器。
type errResolver struct{}

func (errResolver) LookupIP(context.Context, string, string) ([]net.IP, error) {
	return nil, errors.New("解析失败（测试解析器）")
}

// resolverFunc 把函数适配成 URLResolver（便于逐例构造）。
type resolverFunc func(ctx context.Context, network, host string) ([]net.IP, error)

func (f resolverFunc) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	return f(ctx, network, host)
}

// checkChain 逐跳校验（注入确定性解析器）。
//
// 逐跳校验里**每一跳**都要解析一次域名，所以「链条判得对不对」此前同样被
// 绑在「这台机器此刻能不能解析这些域名」上：起始跳公网名 + 相对 Location 的
// 干净链，用例能不能过取决于此刻的网络。
func checkChain(start string, hops []string, allow Allow, maxHops int) error {
	return CheckChainWithResolver(context.Background(), start, hops, allow, maxHops, fakeResolver{})
}

// TestCheckURLUsesInjectedResolver 反向验证：注入的解析结果必须真的被用。
//
// 注入一个把公网名解析成**私网地址**的解析器，判定必须拒——若判定仍然走
// 真实 DNS（或者干脆不看注入结果），这条会绿着过，而「注入没生效」这件事
// 根本没人断言。
func TestCheckURLUsesInjectedResolver(t *testing.T) {
	priv := fakeResolver{"public.example": {net.ParseIP("10.0.0.7")}}
	err := CheckURLWithResolver(t.Context(), "https://public.example/x", Allow{Private: false}, priv)
	if err == nil {
		t.Fatal("注入的解析结果落在私网时必须拒（否则判定没用注入结果）")
	}
	// 断言必须落在**拒绝理由**上：只看「有错」的话，「解析失败」也会蒙混过关
	// ——而那正是「判定没用注入结果」时的形态（真 DNS 解析不出这个名字）。
	if !strings.Contains(err.Error(), "出站目标已拒绝") || strings.Contains(err.Error(), "出站目标解析失败") {
		t.Errorf("红点应是「解析成功但目标已拒绝」（实得 %v）", err)
	}
	// 同一个名字、同一个接缝，换成公网地址 ⇒ 放行。两条合起来才证明
	// 「结论随注入结果变」，而不是「这个 URL 恰好总被拒/总被放行」。
	pub := fakeResolver{"public.example": {net.ParseIP("8.8.8.8")}}
	if err := CheckURLWithResolver(t.Context(), "https://public.example/x", Allow{Private: false}, pub); err != nil {
		t.Fatalf("注入的公网地址应放行: %v", err)
	}
}

// TestCheckURLInjectedResolverFailure 解析失败必须报「出站目标解析失败」。
//
// 断言落在错误文本上：解析失败这一支此前只能靠外网抖动触发，且红点是
// 「no such host」——与「目标已拒绝」混在一起时，分不出是判定拒的还是
// 解析没成。
func TestCheckURLInjectedResolverFailure(t *testing.T) {
	err := CheckURLWithResolver(t.Context(), "https://nowhere.example/x", Allow{}, errResolver{})
	if err == nil {
		t.Fatal("解析失败必须报错")
	}
	if !strings.Contains(err.Error(), "出站目标解析失败") {
		t.Errorf("红点应是「出站目标解析失败」（实得 %v）", err)
	}
}

// TestCheckURLLiteralSkipsResolver IP 字面量不走解析器。
func TestCheckURLLiteralSkipsResolver(t *testing.T) {
	called := false
	boom := resolverFunc(func(context.Context, string, string) ([]net.IP, error) {
		called = true
		return nil, errors.New("解析器不该被调用")
	})
	if err := CheckURLWithResolver(t.Context(), "http://10.0.0.5/x", Allow{Private: true}, boom); err != nil {
		t.Fatalf("私网地址在放行面下应通过: %v", err)
	}
	if called {
		t.Fatal("IP 字面量不得走解析器")
	}
}

// TestCheckURLNilResolverKeepsDefaultPath nil 接缝 ⇒ 缺省解析器（既有行为不变）。
//
// 这里刻意**不**拿真实域名去验「nil 真的走了系统解析器」——那正是本轮要
// 从用例里拆掉的外网依赖。用 IP 字面量走一遍 nil 分支：它证明的是「nil
// 接缝不改变既有调用点的行为」，而「nil 时用 net.DefaultResolver」由
// lookupIP 这一处实现承担（唯一真相）。
func TestCheckURLNilResolverKeepsDefaultPath(t *testing.T) {
	if err := CheckURLWithResolver(t.Context(), "http://10.0.0.5/x", Allow{Private: true}, nil); err != nil {
		t.Fatalf("nil 接缝下私网地址在放行面内应通过: %v", err)
	}
	if err := CheckURLWithResolver(t.Context(), "http://169.254.169.254/x", Allow{Private: true}, nil); err == nil {
		t.Fatal("nil 接缝下链路本地仍须拒（放行旗标不豁免它）")
	}
}

// TestCheckChainUsesInjectedResolver 逐跳校验同样走注入的解析器。
//
// 单跳判定面补了接缝而链条面没补时，这条会绿着过——而链条用例当时仍靠真实
// DNS（example.com）成立，正是本轮要拆掉的依赖。
func TestCheckChainUsesInjectedResolver(t *testing.T) {
	// 两个名字：起始跳走公网的那个（放行），被拒的那一跳走私网的那个。
	// 只用一个名字时两处判定面会互相遮住——起始跳先拒掉，后面那处根本没走到，
	// 改坏它这条用例照样绿（实测过）。
	res := fakeResolver{
		"public.example":  {net.ParseIP("8.8.8.8")},
		"private.example": {net.ParseIP("10.0.0.7")},
	}
	// 两种形态各自盖一处判定面：起始跳单判（hops 为空 ⇒ 只有起始 URL 过判定面）
	// 与逐跳（hops 非空 ⇒ 后续跳也过判定面）。
	for _, tc := range []struct {
		name    string
		start   string
		hops    []string
		wantHop int
	}{
		{"起始跳单判", "https://private.example/start", nil, 1},
		{"逐跳", "https://public.example/start", []string{"http://private.example/x"}, 2},
	} {
		err := CheckChainWithResolver(t.Context(), tc.start, tc.hops, Allow{Private: false}, 0, res)
		if err == nil {
			t.Fatalf("%s: 注入的解析结果落在私网时链条必须拒（否则逐跳校验没用注入结果）", tc.name)
		}
		// 落在**拒绝理由**上：「有错」不够——「解析失败」也会让这条绿着过，
		// 而那正是逐跳校验没用注入结果时的形态。
		if !strings.Contains(err.Error(), "出站目标已拒绝") || strings.Contains(err.Error(), "出站目标解析失败") {
			t.Errorf("%s: 红点应是「解析成功但目标已拒绝」（实得 %v）", tc.name, err)
		}
		// 并钉住**是哪一跳**被拒：起始跳单判 ⇒ Hop=1，逐跳 ⇒ Hop=2。
		var hd *HopDeniedError
		if !errors.As(err, &hd) || hd.Hop != tc.wantHop {
			t.Errorf("%s: 应报第 %d 跳被拒（实得 %v）", tc.name, tc.wantHop, err)
		}
	}
}

// TestCheckChainNilResolverKeepsDefaultPath nil 接缝 ⇒ 缺省解析器。
func TestCheckChainNilResolverKeepsDefaultPath(t *testing.T) {
	if err := CheckChainWithResolver(t.Context(), "http://127.0.0.1:9/a", []string{"/b"}, Allow{Private: true, Loopback: true}, 0, nil); err != nil {
		t.Fatalf("nil 接缝下私网地址在放行面内应通过: %v", err)
	}
}
