package egressproxy_test

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/oagentkit/guardx/egressproxy"
)

// 本文件钉 guardx#119 的回归：AllowHosts 含 "*"（黑名单模式）时，IP 字面量
// 的「名单命中即显式意图」豁免把 IP 围栏整个跳过——169.254.169.254 /
// 127.0.0.1 一类以字面量形态直接放行，而同一个地址以域名形态出现会被
// DNS 围栏拒掉（#96 修复说明不允许的「换个写法结论相反」形态）。
// 修后：字面量只有**逐字**命中名单才享显式意图豁免；通配命中（"*" / "*.x"）
// 一律落到 IP 围栏，且该判定不被 SkipDNSCheck 豁免（它不是解析判定）。

// TestWildcardAllowsIPLiteralMustPassIPFence issue 实测复现场景：
// AllowHosts=["*"] + DenyHosts 的黑名单模式下，内网/元数据/回环字面量必须全拒。
func TestWildcardAllowsIPLiteralMustPassIPFence(t *testing.T) {
	p := egressproxy.Policy{AllowHosts: []string{"*"}}
	cases := []struct {
		name string
		host string
	}{
		{"云元数据", "169.254.169.254"},
		{"回环", "127.0.0.1"},
		{"私网", "10.0.0.9"},
		{"CGNAT", "100.64.0.1"},
		{"回环 v6", "::1"},
		{"ULA v6", "fd00::1"},
	}
	for _, tc := range cases {
		addrs, err := p.PermitResolving(context.Background(), tc.host, 80)
		if err == nil {
			t.Fatalf("黑名单模式下 %s（%s）必须被 IP 围栏拒掉（#119），实得 addrs=%v", tc.name, tc.host, addrs)
		}
		if addrs != nil {
			t.Fatalf("%s 被拒时不得返回已检地址，实得 %v", tc.host, addrs)
		}
	}
}

// TestWildcardStillAllowsPublicIP 黑名单模式对公网字面量照常放行——
// 收紧的只是「非公网字面量借 "*" 免检」的口子，不是黑名单模式本身。
func TestWildcardStillAllowsPublicIP(t *testing.T) {
	p := egressproxy.Policy{AllowHosts: []string{"*"}}
	addrs, err := p.PermitResolving(context.Background(), "93.184.216.34", 80)
	if err != nil {
		t.Fatalf("公网字面量在黑名单模式下应放行，实得 %v", err)
	}
	if len(addrs) != 1 || addrs[0] != netip.MustParseAddr("93.184.216.34") {
		t.Fatalf("应返回已检地址供拨号钉住，实得 %v", addrs)
	}
}

// TestExactIPLiteralEntryKeepsExplicitIntent 逐字写进名单的 IP 字面量照旧
// 放行——「写进名单本身就是调用方对这个地址的显式意图」的承诺必须保住。
func TestExactIPLiteralEntryKeepsExplicitIntent(t *testing.T) {
	p := egressproxy.Policy{AllowHosts: []string{"169.254.169.254"}}
	addrs, err := p.PermitResolving(context.Background(), "169.254.169.254", 80)
	if err != nil {
		t.Fatalf("逐字名单条目应享显式意图豁免，实得 %v", err)
	}
	if len(addrs) != 1 || addrs[0] != netip.MustParseAddr("169.254.169.254") {
		t.Fatalf("应返回该地址本身供拨号钉住，实得 %v", addrs)
	}
}

// TestSkipDNSCheckDoesNotExemptIPLiteral 字面量判定不是 DNS 判定：
// SkipDNSCheck 跳过的是域名解析，黑名单模式下的 IP 围栏照常执行。
func TestSkipDNSCheckDoesNotExemptIPLiteral(t *testing.T) {
	p := egressproxy.Policy{AllowHosts: []string{"*"}, SkipDNSCheck: true}
	for _, h := range []string{"169.254.169.254", "127.0.0.1", "::1"} {
		if _, err := p.PermitResolving(context.Background(), h, 80); err == nil {
			t.Fatalf("SkipDNSCheck=true 时 %s 仍须被 IP 围栏拒掉（#119）", h)
		}
	}
	// 公网字面量照常放行（返回已检地址，非 (nil, nil)）。
	addrs, err := p.PermitResolving(context.Background(), "93.184.216.34", 80)
	if err != nil || len(addrs) != 1 {
		t.Fatalf("SkipDNSCheck=true 时公网字面量应放行并返回已检地址，实得 %v, %v", addrs, err)
	}
}

// TestSkipDNSCheckStillRejectsExoticLiteral exotic IPv4 词法形态
// （0177.0.0.1——inet_aton 语义会解析成回环）的拒绝是**字面量词法判定**，
// 不是解析判定：SkipDNSCheck=true 不得让它借道。
func TestSkipDNSCheckStillRejectsExoticLiteral(t *testing.T) {
	for _, allow := range [][]string{{"*"}, {"0177.0.0.1"}} {
		p := egressproxy.Policy{AllowHosts: allow, SkipDNSCheck: true}
		if _, err := p.PermitResolving(context.Background(), "0177.0.0.1", 80); err == nil {
			t.Fatalf("exotic IPv4 形态不得借 SkipDNSCheck 放行（allow=%v）", allow)
		}
	}
}

// TestExactDomainEntryUnaffected 域名条目的既有语义不变：逐字/通配命中
// 域名照走 DNS 围栏（stub 解析到公网 ⇒ 放行，已检地址正常返回）。
func TestExactDomainEntryUnaffected(t *testing.T) {
	res := &stubResolver{ips: []net.IP{net.ParseIP("93.184.216.34")}}
	p := egressproxy.Policy{AllowHosts: []string{"api.example.com"}, Resolver: res}
	addrs, err := p.PermitResolving(context.Background(), "api.example.com", 443)
	if err != nil {
		t.Fatalf("名单内域名解析到公网应放行，实得 %v", err)
	}
	if len(addrs) != 1 || addrs[0] != netip.MustParseAddr("93.184.216.34") {
		t.Fatalf("应返回已检地址，实得 %v", addrs)
	}
	if res.calls.Load() == 0 {
		t.Fatal("域名条目必须经过 DNS 围栏（解析）")
	}
}
