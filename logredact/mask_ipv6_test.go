package logredact

import (
	"strings"
	"testing"
)

// 本文件钉 guardx#100 的回归：Masker 的默认模式必须覆盖 IPv6 字面量。
// Masker 是「低敏感拓扑标识掩码器」，进 LLM 前把拓扑标识换成 «Tn»——
// 双栈/K8s 环境里 IPv6（fe80::1、2001:db8::5、::1、链路本地 zone 形）
// 是常态拓扑标识，v0.23.0 的默认模式只有 ipv4Re，IPv6 原文直通 LLM 输入，
// 正是本包纪律里的事故方向（漏 mask 才是事故）。

// TestMaskerIPv6MaskedLikeIPv4 issue 实测复现场景：两个 IPv6 泄漏、IPv4 被掩。
func TestMaskerIPv6MaskedLikeIPv4(t *testing.T) {
	m := NewMasker()
	in := "gateway fe80::1 and node 2001:db8::5 behind 10.0.0.5"
	masked := m.Mask(in)
	for _, leak := range []string{"fe80::1", "2001:db8::5", "10.0.0.5"} {
		if strings.Contains(masked, leak) {
			t.Fatalf("拓扑标识 %q 泄漏进掩码输出: %q", leak, masked)
		}
	}
	if got := m.Count(); got != 3 {
		t.Fatalf("三个地址应各得一令牌，count=%d", got)
	}
	if back := m.Restore(masked); back != in {
		t.Fatalf("回填应无损:\n got %q\nwant %q", back, in)
	}
}

// TestMaskerIPv6FormsTable 各 IPv6 词法形态：掩掉、且回填无损。
func TestMaskerIPv6FormsTable(t *testing.T) {
	cases := []struct {
		name string
		in   string
		leak string
	}{
		{"前压缩形", "peer ::1 ready", "::1"},
		{"括号形", "host [::1]:8080 up", "::1"},
		{"zone 形", "via fe80::1%eth0", "fe80::1%eth0"},
		{"IPv4 映射形", "mapped ::ffff:10.0.0.5", "::ffff:10.0.0.5"},
		{"NAT64 形", "nat64 64:ff9b::192.0.2.33", "64:ff9b::192.0.2.33"},
		{"大写十六进制", "db8 2001:0DB8::5", "2001:0DB8::5"},
		{"完整形", "full 1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8"},
	}
	for _, tc := range cases {
		m := NewMasker()
		masked := m.Mask(tc.in)
		if strings.Contains(masked, tc.leak) {
			t.Errorf("%s: %q 泄漏: %q", tc.name, tc.leak, masked)
			continue
		}
		if back := m.Restore(masked); back != tc.in {
			t.Errorf("%s: 回填应无损:\n got %q\nwant %q", tc.name, back, tc.in)
		}
	}
}

// TestMaskerIPv6SentenceDotKept 句点紧跟地址（prose 常态）：地址掩掉、句点保留。
func TestMaskerIPv6SentenceDotKept(t *testing.T) {
	m := NewMasker()
	in := "gateway is ::1."
	masked := m.Mask(in)
	if strings.Contains(masked, "::1") {
		t.Fatalf("IPv6 泄漏: %q", masked)
	}
	if !strings.HasSuffix(masked, "».") {
		t.Fatalf("句点应保留在令牌之后: %q", masked)
	}
	if back := m.Restore(masked); back != in {
		t.Fatalf("回填应无损:\n got %q\nwant %q", back, in)
	}
}

// TestMaskerNonAddressesUntouched 相邻词法的非地址形态不得误掩：
// 候选捕获 + net.ParseIP 精确验证，判负的原样保留（MAC / 时刻 / 作用域符 /
// 比值 / 带端口的 URL）。
func TestMaskerNonAddressesUntouched(t *testing.T) {
	for _, in := range []string{
		"mac aa:bb:cc:dd:ee:ff down",
		"at 12:30:45 sharp",
		"scope std::cafe",
		"path a::b::c",
		"ratio 16:9:9",
		"url https://example.com:8080/x",
	} {
		m := NewMasker()
		if got := m.Mask(in); got != in {
			t.Errorf("非地址形态被误掩: %q → %q", in, got)
		}
	}
}

// TestMaskerIPv6DeterministicToken 同一 IPv6 地址恒同令牌（与 IPv4 同纪律）。
func TestMaskerIPv6DeterministicToken(t *testing.T) {
	m := NewMasker()
	first := m.Mask("first 2001:db8::5")
	second := m.Mask("second 2001:db8::5")
	tok := tokenRe.FindString(first)
	if tok == "" {
		t.Fatalf("掩码输出应含令牌: %q", first)
	}
	if !strings.Contains(second, tok) {
		t.Fatalf("同址应同令牌 %s: first=%q second=%q", tok, first, second)
	}
	if got := m.Count(); got != 1 {
		t.Fatalf("同址只应签发一枚令牌，count=%d", got)
	}
}
