package egress

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

// stubResolver 固定解析结果的注入 stub（绕开真实网络）。
type stubResolver struct {
	ips []net.IP
	err error
}

func (s stubResolver) LookupIP(context.Context, string, string) ([]net.IP, error) {
	return s.ips, s.err
}

// TestCheckResolvingBlocksPrivateResolution 回归（#60）：解析到内网的域名
// 必须被 IP 策略拦下——字面量层拦不住的整类绕过（nip.io、内网域名、
// rebinding）都靠这一层兜住。
func TestCheckResolvingBlocksPrivateResolution(t *testing.T) {
	cases := []struct {
		name      string
		host      string
		ips       []net.IP
		wantTitle string
	}{
		{"云元数据解析", "169.254.169.254.nip.io", []net.IP{net.ParseIP("169.254.169.254")}, "链路本地"},
		{"解析到回环", "rebind.evil.test", []net.IP{net.ParseIP("127.0.0.1")}, "回环"},
		{"解析到私网", "intranet.corp.test", []net.IP{net.ParseIP("10.1.2.3")}, "私网"},
		{"解析到 CGNAT", "cgnat.test", []net.IP{net.ParseIP("100.64.0.1")}, "保留段"},
		{"解析到保留段", "bench.test", []net.IP{net.ParseIP("198.18.0.1")}, "保留段"},
		{"解析到 ULA", "ula.test", []net.IP{net.ParseIP("fd00::1")}, "唯一本地"},
		// 多条结果任一命中即阻断——只放行混在公网答案里的那条等于没拦
		{"多结果混入私网", "mixed.test", []net.IP{net.ParseIP("93.184.216.34"), net.ParseIP("192.168.0.1")}, "私网"},
		{"IPv4-mapped 形态", "mapped.test", []net.IP{net.ParseIP("::ffff:169.254.169.254")}, "链路本地"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CheckHostResolving(context.Background(), tc.host, Policy{}, stubResolver{ips: tc.ips})
			if err == nil {
				t.Fatalf("%s 解析到禁止 IP 应阻断", tc.host)
			}
			var be *BlockedError
			if !errors.As(err, &be) {
				t.Fatalf("%s 应为 BlockedError，得 %T：%v", tc.host, err, err)
			}
			if !strings.Contains(be.Reason, tc.wantTitle) {
				t.Fatalf("%s 命中原因 %q 不含 %q", tc.host, be.Reason, tc.wantTitle)
			}
			if be.Host != tc.host {
				t.Fatalf("留痕 Host 应保留原域名，实得 %q", be.Host)
			}
		})
	}
}

// TestCheckResolvingFailClosed 解析失败与空结果都必须阻断——「解析不出来」
// 与「解析到禁止 IP」同为不可放行的未知，任何一个当放行处理都是把
// 判定权交给网络环境。
func TestCheckResolvingFailClosed(t *testing.T) {
	if _, err := CheckHostResolving(context.Background(), "nx.test", Policy{}, stubResolver{err: errors.New("dns 超时")}); err == nil {
		t.Fatal("解析失败应 fail-closed 阻断")
	}
	if _, err := CheckHostResolving(context.Background(), "empty.test", Policy{}, stubResolver{}); err == nil {
		t.Fatal("解析结果为空应 fail-closed 阻断")
	}
}

// TestCheckResolvingAllowsPublic 公网解析结果放行，且返回全部已检地址
// 供调用方拨号钉住（闭合 TOCTOU 的前提）。
func TestCheckResolvingAllowsPublic(t *testing.T) {
	ips := []net.IP{net.ParseIP("93.184.216.34"), net.ParseIP("2606:4700::1111")}
	got, err := CheckHostResolving(context.Background(), "example.test", Policy{}, stubResolver{ips: ips})
	if err != nil {
		t.Fatalf("公网解析应放行：%v", err)
	}
	if len(got) != 2 {
		t.Fatalf("应返回全部已检地址（供拨号钉住），实得 %v", got)
	}
}

// TestCheckResolvingLiteralHosts IP 字面量与 localhost 走与字面量判定
// 相同的口径，返回值可直接用于拨号。
func TestCheckResolvingLiteralHosts(t *testing.T) {
	got, err := CheckHostResolving(context.Background(), "8.8.8.8", Policy{}, nil)
	if err != nil || len(got) != 1 || got[0].String() != "8.8.8.8" {
		t.Fatalf("公网 IP 字面量应放行并回带地址，实得 %v %v", got, err)
	}
	if _, err := CheckHostResolving(context.Background(), "10.0.0.1", Policy{}, nil); err == nil {
		t.Fatal("私网 IP 字面量应阻断（与 CheckHost 同口径）")
	}
	// NAT64 载体归一后回带 IPv4 形态
	got, err = CheckHostResolving(context.Background(), "64:ff9b::7f00:1", Policy{}, nil)
	if err == nil {
		t.Fatal("NAT64 内嵌回环应阻断")
	}
	// exotic 词法在解析前就拒（进了 resolver 会被 inet_aton 解析成回环）
	if _, err := CheckHostResolving(context.Background(), "127.1", Policy{}, stubResolver{}); err == nil {
		t.Fatal("exotic IPv4 词法应阻断")
	}
	// localhost：零值拒，AllowLoopback 放行（解析结果恒为回环）
	if _, err := CheckHostResolving(context.Background(), "localhost", Policy{}, stubResolver{ips: []net.IP{net.ParseIP("127.0.0.1")}}); err == nil {
		t.Fatal("零值应拒 localhost 域")
	}
	if _, err := CheckHostResolving(context.Background(), "localhost", SelfService, stubResolver{ips: []net.IP{net.ParseIP("127.0.0.1")}}); err != nil {
		t.Fatalf("AllowLoopback 应放行 localhost：%v", err)
	}
	if _, err := CheckHostResolving(context.Background(), "", Policy{}, nil); err == nil {
		t.Fatal("空 host 应 fail-closed")
	}
}

// TestCheckResolvingSchemeGuard 解析变体与字面量入口共用同一 scheme
// 白名单——非 http(s) 的 URL 没有理由进 DNS 判定。
func TestCheckResolvingSchemeGuard(t *testing.T) {
	for _, u := range []string{
		"file://localhost/etc/passwd",
		"gopher://evil.test/_FLUSHALL",
		"ftp://corp.test/pub",
		"example.com/relative", // 空 scheme（相对 URL）
	} {
		if _, err := CheckResolving(context.Background(), u, Policy{}, stubResolver{ips: []net.IP{net.ParseIP("93.184.216.34")}}); err == nil {
			t.Errorf("%s 非 http(s) scheme 应阻断", u)
		}
	}
	// http(s) 放行面不受影响
	if _, err := CheckResolving(context.Background(), "https://example.test/", Policy{}, stubResolver{ips: []net.IP{net.ParseIP("93.184.216.34")}}); err != nil {
		t.Errorf("https 公网目标应放行：%v", err)
	}
}

// TestPolicyCheckResolvingDerivesSameFace Policy 值派生的解析入口与包级
// 入口语义一致——写面与拨号层共用同一个放行面值，不允许分叉。
func TestPolicyCheckResolvingDerivesSameFace(t *testing.T) {
	r := stubResolver{ips: []net.IP{net.ParseIP("10.0.0.1")}}
	if _, err := PublicOnly.CheckResolving(context.Background(), "http://intranet.corp.test/", r); err == nil {
		t.Fatal("PublicOnly 应拒私网解析结果")
	}
	if _, err := PrivateNoLoopback.CheckResolving(context.Background(), "http://intranet.corp.test/", r); err != nil {
		t.Fatalf("PrivateNoLoopback 应放行私网解析结果：%v", err)
	}
}
