package logredact

import (
	"strings"
	"testing"
)

// 本文件钉 guardx#133 的回归：ipv6Re 左边界必须放行冒号——「标签：地址」
// 紧贴形态（host:fe80::1、node:2001:db8::5）此前匹配不上，地址原文直通
// LLM 输入。候选本就有 net.ParseIP 精确验证兜底，边界排除冒号防不了任何
// 真负例，只丢了这一类覆盖。同址恒同令牌：带标签与裸地址同一枚令牌。

// TestMaskerIPv6AfterColonLabel issue 复现：冒号紧贴的 IPv6 掩掉且回填无损。
func TestMaskerIPv6AfterColonLabel(t *testing.T) {
	cases := []struct{ in, leak string }{
		{"connect to host:fe80::1 failed", "fe80::1"},
		{"node:2001:db8::5 down", "2001:db8::5"},
		{"addr=::1 ok", "::1"},
		{"peer:fe80::1%eth0 up", "fe80::1"},
	}
	for _, tc := range cases {
		m := NewMasker()
		masked := m.Mask(tc.in)
		if strings.Contains(masked, tc.leak) {
			t.Errorf("%q: %q 泄漏: %q", tc.in, tc.leak, masked)
			continue
		}
		if back := m.Restore(masked); back != tc.in {
			t.Errorf("%q: 回填应无损:\n got %q\nwant %q", tc.in, back, tc.in)
		}
	}
}

// TestMaskerIPv6ColonLabelSameToken 同一地址两种写法恒同令牌（#100 不变量
// 不因标签形态分裂）。
func TestMaskerIPv6ColonLabelSameToken(t *testing.T) {
	m := NewMasker()
	a := m.Mask("host:fe80::1")
	b := m.Mask("peer fe80::1")
	tokA, tokB := tokenRe.FindString(a), tokenRe.FindString(b)
	if tokA == "" || tokB == "" {
		t.Fatalf("两处都应产生令牌: %q / %q", a, b)
	}
	if tokA != tokB {
		t.Fatalf("同址应同令牌: %q vs %q", a, b)
	}
	if got := m.Count(); got != 1 {
		t.Fatalf("同址只应签发一枚令牌，count=%d", got)
	}
}

// TestMaskerColonBoundaryNegativesUntouched 冒号放开后的反证：时刻、MAC、
// 作用域符、冒号链等非地址形态判负原样保留（ParseIP 兜底，不得误掩）。
func TestMaskerColonBoundaryNegativesUntouched(t *testing.T) {
	for _, in := range []string{
		"at 12:30:45 sharp",
		"at 12:30:45:30 sharp", // 时刻后紧跟冒号数字
		"mac aa:bb:cc:dd:ee:ff down",
		"scope std::cafe",
		"path a::b::c",
		"ratio 16:9:9",
		"x:12:30:45 tail", // 标签形态的时刻（剥首个冒号仍判负）
	} {
		m := NewMasker()
		if got := m.Mask(in); got != in {
			t.Errorf("非地址形态被误掩: %q → %q", in, got)
		}
	}
}
