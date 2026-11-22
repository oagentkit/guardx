package netguard

import (
	"time"

	"net"

	"context"

	"strings"
	"testing"

	"github.com/oekit/pkg/errors"
)

func TestCheckURL(t *testing.T) {
	cases := []struct {
		name         string
		url          string
		allowPrivate bool
		allowLoop    bool
		wantErr      bool
	}{
		{"外网 https 放行", "https://oapi.dingtalk.com/send?x=1", true, false, false},
		{"外网 http 放行", "http://example.com/hook", false, false, false},
		{"回环拒绝（外部输入面）", "http://127.0.0.1:8900/api", true, false, true},
		{"回环名拒绝", "http://localhost/x", true, false, true},
		{"回环放行（凭证探测）", "http://127.0.0.1:18940/metrics", true, true, false},
		{"云元数据拒绝", "http://169.254.169.254/latest/meta-data/", true, false, true},
		{"未指定地址拒绝", "http://0.0.0.0/x", true, false, true},
		{"this network 拒绝（.1）", "http://0.1.2.3/x", true, false, true},
		{"this network 拒绝（.255）", "http://0.255.255.255/x", true, false, true},
		{"私网放行（allowPrivate）", "http://192.168.1.10:8080/hook", true, false, false},
		{"私网拒绝（严格档）", "http://10.0.0.5/hook", false, false, true},
		{"非 http scheme 拒绝", "file:///etc/passwd", true, false, true},
		{"缺 host 拒绝", "http:///path", true, false, true},
	}
	for _, tc := range cases {
		// 注入假解析器（#412）：判定路径不再依赖真实外网 DNS——本机负载下解析器
		// 超时/丢包曾让「外网放行」两条假红 30s；判定面与解析来源解耦后用例只测
		// 判据本身。名字/IP 策略用例本就不走到解析。
		err := CheckURLWithResolver(t.Context(), tc.url, Allow{Private: tc.allowPrivate, Loopback: tc.allowLoop}, fakeResolver{})
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: CheckURLWithResolver(%q, %+v) err=%v wantErr=%v", tc.name, tc.url, Allow{Private: tc.allowPrivate, Loopback: tc.allowLoop}, err, tc.wantErr)
		}
	}
}

// fakeResolver 是固定映射的测试解析器：**未登记**的名字一律回落到文档保留公网
// 地址，既不需要外网 DNS，也不会命中私网/回环/元数据名单；**登记过**的名字按
// 登记给。
//
// 键按 DNS 语义归一（大小写不敏感、尾点等价），与真实解析器对齐——否则
// 「http://EXAMPLE.com./x」这类写法会走回落分支，用例测的就不是它想测的那条。
type fakeResolver map[string][]net.IP

func (r fakeResolver) LookupIP(_ context.Context, _, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	key := strings.ToLower(strings.TrimSuffix(host, "."))
	if ips, ok := r[key]; ok {
		return ips, nil
	}
	return []net.IP{net.ParseIP("93.184.216.34")}, nil
}

// TestCheckURLBlockedNameBeforeDNS 名字层必须在 DNS 之前判。
//
// 断言点是错误类型：命中名字名单时必须给出 BlockedNameError，而不是
// 「解析失败」——这些名字在公网 DNS 上本来就解不出来，若结论来自解析器就说明
// 名字层没生效（或者只在解析成功时才判，等于给攻击者留了一条 DNS 可控的旁路）。
func TestCheckURLBlockedNameBeforeDNS(t *testing.T) {
	cases := []struct{ name, url string }{
		{"精确名（元数据）", "http://metadata.google.internal/x"},
		{"精确名（元数据别名）", "http://metadata.goog/x"},
		{"精确名（容器网桥）", "http://host.docker.internal/x"},
		{"精确名（容器网关）", "http://gateway.docker.internal/x"},
		{"后缀族（.internal）", "http://svc.internal/x"},
		{"后缀族（.local）", "http://printer.local/x"},
		{"后缀族（.localdomain，点分边界）", "http://svc.localdomain/x"},
		{"后缀族（.lan）", "http://box.lan/x"},
		{"大小写与尾点归一化", "http://Metadata.Google.Internal./x"},
	}
	for _, tc := range cases {
		err := CheckURLWith(tc.url, Allow{Private: false, Loopback: false})
		var bn *BlockedNameError
		if !errors.As(err, &bn) {
			t.Errorf("%s: 应在解析前被名字层拒（BlockedNameError），实得 %v", tc.name, err)
			continue
		}
		if !errors.Is(err, ErrBlockedName) {
			t.Errorf("%s: 应 Unwrap 出 ErrBlockedName 哨兵，实得 %v", tc.name, err)
		}
		if bn.Host == "" {
			t.Errorf("%s: 拒绝结论应带 host 便于留痕", tc.name)
		}
	}
}

// TestLocaldomainSuffixBoundary `.localdomain` 是 2026-10-19 补入的默认后缀
// （对齐上游 oekit/pkg/urlguard v0.15.0：它把该后缀归为「本就不是合法出站目标」
// 的保留段，而本包此前漏判，且 `.local` 的点分边界匹配不到 `svc.localdomain`）。
// 此处钉两件事：命中的是 `.localdomain` 这个后缀本身，以及匹配仍是点分边界、
// 没退化成「含 localdomain 即拦」的子串比较。
//
// 命中与反向断言都走 checkHostName：未命中意味着还要继续解析，走 CheckURL 会真去
// 查 DNS。这里要验的只是名单匹配本身，不必付网络的代价。
func TestLocaldomainSuffixBoundary(t *testing.T) {
	for _, h := range []string{
		"svc.localdomain",
		"a.b.localdomain",
		"MiXeD.Example.LocalDomain", // 大小写与多级标签
		"svc.localdomain.",          // 尾点写法
	} {
		if err := checkHostName(h, false); !errors.Is(err, ErrBlockedName) {
			t.Errorf("主机名 %q 应命中 .localdomain 后缀，实得 %v", h, err)
		}
	}
	for _, h := range []string{
		"localdomain",                // 顶级域本身不该因本后缀被整片拒
		"notlocaldomain.example.com", // 子串不等于后缀
		"mylocaldomain.net",
	} {
		if err := checkHostName(h, false); err != nil {
			t.Errorf("主机名 %q 不应命中 .localdomain（点分边界，非子串），实得 %v", h, err)
		}
	}
}

// TestCheckURLBlockedNameIgnoresAllowFlags 非回环族名单项不看放行旗标：
// allowPrivate/allowLoopback 都为 true（放行面参数）时依然拒绝。
// 这条断言钉住「allowPrivate 只放行私网地址、不放行私有命名空间」的口径。
//
// 断言必须落在「拒绝来自名字层」上（ErrBlockedName），不能只断言「有错」——
// 名单里的名字在真实 DNS 上大多也解不出来，只看有没有错的话，
// 「这些名字被改成旗标豁免、最终死在解析失败」也会蒙混过关。
func TestCheckURLBlockedNameIgnoresAllowFlags(t *testing.T) {
	for _, u := range []string{
		"http://metadata.google.internal/x",
		"http://host.docker.internal/x",
		"http://svc.internal/x",
		"http://printer.local/x",
		"http://svc.localdomain/x",
		"http://box.lan/x",
	} {
		if err := CheckURLWith(u, Allow{Private: true, Loopback: true}); !errors.Is(err, ErrBlockedName) {
			t.Errorf("%s: 放行面参数下仍应由名字层拒，实得 %v", u, err)
		}
	}
}

// TestCheckURLLoopbackFamilyFollowsAllowFlag 回环族名字是 127.0.0.1 的名字形式，
// 必须与回环地址同待遇：allowLoopback=true 放行、false 拒绝。
// 少了这条，新增名字层会把「allowLoopback=true 够不到自身服务」变成回归。
func TestCheckURLLoopbackFamilyFollowsAllowFlag(t *testing.T) {
	// 解析结果由注入的解析器给出（127.0.0.1），因此这条断言**不再依赖解析器的
	// magic**——此前它靠 unix 的 systemd-resolved / macOS resolver 把
	// *.localhost 导回环，windows 上根本没有这个特判，用例只能按平台跳过
	//（windows CI 那一格是「跳过」而不是「验过」）。接上接缝后，放行语义在
	// 所有平台上被同一条断言钉住。
	loop := fakeResolver{
		"localhost":     {net.ParseIP("127.0.0.1")},
		"api.localhost": {net.ParseIP("127.0.0.1")},
	}
	if err := CheckURLWithResolver(t.Context(), "http://localhost:9/x", Allow{Private: true, Loopback: true}, loop); err != nil {
		t.Fatalf("allowLoopback=true 时回环族名字应放行: %v", err)
	}
	if err := CheckURLWithResolver(t.Context(), "http://api.localhost:9/x", Allow{Private: true, Loopback: true}, loop); err != nil {
		t.Fatalf("allowLoopback=true 时 .localhost 后缀应放行: %v", err)
	}
	for _, u := range []string{"http://localhost/x", "http://api.localhost/x"} {
		if err := CheckURLWith(u, Allow{Private: true, Loopback: false}); !errors.Is(err, ErrBlockedName) {
			t.Errorf("%s: allowLoopback=false 时应被名字层拒，实得 %v", u, err)
		}
	}
}

// TestCheckURLPublicNameAllowed 名字层不得误伤公网名（含大小写/尾点写法）。
func TestCheckURLPublicNameAllowed(t *testing.T) {
	for _, u := range []string{"https://example.com/hook", "http://EXAMPLE.com/x", "http://example.com./x"} {
		if err := CheckURLWithResolver(t.Context(), u, Allow{Private: false, Loopback: false}, fakeResolver{}); err != nil {
			t.Errorf("%s: 公网名应放行，实得 %v", u, err)
		}
	}
}

// TestCheckChainBlockedNameEveryHop 名字层对每一跳都生效（CheckChain 逐跳过 CheckURL）。
func TestCheckChainBlockedNameEveryHop(t *testing.T) {
	err := CheckChainWith("https://example.com/start", []string{"http://svc.internal/x"}, Allow{Private: false, Loopback: false}, 0)
	var hd *HopDeniedError
	if !errors.As(err, &hd) || hd.Hop != 2 {
		t.Fatalf("第二跳跳进拦截后缀应报 Hop=2，实得 %v", err)
	}
	if !errors.Is(err, ErrBlockedName) {
		t.Errorf("应能判定出是名字层拒绝（Unwrap 链完整），实得 %v", err)
	}
}

// TestCheckURLWithCtxPropagatesCancel 校验面的解析带 ctx：调用方取消要能
// 打断一次卡住的解析（dial.go 当年同一判据只修了拨号层，这一半补齐）。
// 用一个挂着不放的假解析器模拟 DNS 黑洞——无 ctx 形态在这里会永远挂住，
// Ctx 形态在取消后立即返回。
func TestCheckURLWithCtxPropagatesCancel(t *testing.T) {
	// 挂住解析器：只响应 ctx.Done，否则永不返回。
	//
	// dialed 是**可观测事实**：解析面真的被拨过号了（而不是「睡了 100ms
	// 大概进去了」）——尺子必须是事实，不是墙钟窗口。
	dialed := make(chan struct{}, 1)
	blocking := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			select {
			case dialed <- struct{}{}:
			default:
			}
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	old := net.DefaultResolver
	net.DefaultResolver = blocking
	t.Cleanup(func() { net.DefaultResolver = old })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- CheckURLWithCtx(ctx, "https://blackhole.example.com", Allow{})
	}()
	// 等解析面真的进解析（可观测事实：假解析器被拨过号），然后取消。
	select {
	case <-dialed:
	case <-time.After(5 * time.Second):
		t.Fatal("校验面未在时限内进入解析")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("取消后必须返回错误，而不是解析成功")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("取消传播失效：Check 在假黑洞解析器上仍然挂住（无上限解析回来了）")
	}
}

// TestCheckURLWithNilCtxBounded nil ctx 等价 10s 上限形态：不挂死。
func TestCheckURLWithNilCtxBounded(t *testing.T) {
	blocking := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	old := net.DefaultResolver
	net.DefaultResolver = blocking
	t.Cleanup(func() { net.DefaultResolver = old })

	start := time.Now()
	// 钉的就是 nil-ctx 契约（doc：nil = 10s 上限形态），豁免 SA1012。
	_ = CheckURLWithCtx(nil, "https://blackhole.example.com", Allow{}) //nolint:staticcheck // SA1012: nil ctx is the contract under test
	if d := time.Since(start); d > 15*time.Second {
		t.Fatalf("nil ctx 形态应在 10s 上限内返回，实耗 %s", d)
	}
}
