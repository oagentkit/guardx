package logredact

import (
	"strings"
	"testing"
)

// 本文件钉 guardx#122 的回归：Masker 的精确串盲替换阶段原先对**全部**已
// 注册原文（含 IP 模式动态注册的）做 strings.ReplaceAll——先见短 IP 后见
// 以它为中部子串的长 IP 时，长 IP 被盲替换成「残段+旧令牌」（11.2.3.4 →
// 1«T1»）：既非任一原址形态、令牌外残留原文，还破坏「同址恒同令牌」
//（#100 自述不变量）与下游按 «Tn» 形态消费令牌的 Count/UnmaskValue/报告
// 渲染。修后：精确阶段只处理 AddSecret 显式串；动态注册的 IP 由 IP 模式
// 重新整段命中（maskLocked 去重 ⇒ 同址恒同令牌跨调用成立）。

// TestMaskerShortIPThenSupersetIP issue 实测复现场景：先短 IP 后其超集 IP。
func TestMaskerShortIPThenSupersetIP(t *testing.T) {
	m := NewMasker()
	if got := m.Mask("gw 1.2.3.4"); got != "gw «T1»" {
		t.Fatalf("首轮应掩短 IP，实得 %q", got)
	}
	got := m.Mask("server 11.2.3.4")
	if got != "server «T2»" {
		t.Fatalf("长 IP 必须获得自己的整址令牌（修复前为残段 1«T1»），实得 %q", got)
	}
	if strings.Contains(got, "«T1»") {
		t.Fatalf("短 IP 令牌不得出现在长 IP 的掩码里：%q", got)
	}
	if m.Count() != 2 {
		t.Fatalf("两个不同地址应有两个令牌，实得 %d", m.Count())
	}
}

// TestMaskerSameIPStableAcrossCalls 同址恒同令牌（#100 不变量）跨调用成立：
// 短 IP 与长 IP 先后出现后再遇短 IP，仍得原令牌。
func TestMaskerSameIPStableAcrossCalls(t *testing.T) {
	m := NewMasker()
	_ = m.Mask("gw 1.2.3.4")
	_ = m.Mask("server 11.2.3.4")
	if got := m.Mask("retry to 1.2.3.4 ok"); got != "retry to «T1» ok" {
		t.Fatalf("同址必须恒同令牌，实得 %q", got)
	}
	if got := m.Mask("again 11.2.3.4 done"); got != "again «T2» done" {
		t.Fatalf("超集地址同址必须恒同令牌，实得 %q", got)
	}
}

// TestMaskerFamilyCoexistence K8s/工具输出常态：私有网段 10.0.0.1 /
// 10.0.0.11 / 10.0.0.111 家族并存，任一顺序进出都不得产生残段。
func TestMaskerFamilyCoexistence(t *testing.T) {
	m := NewMasker()
	for _, s := range []string{"pod 10.0.0.1", "pod 10.0.0.11", "pod 10.0.0.111"} {
		got := m.Mask(s)
		if !strings.HasPrefix(got, "pod «T") || !strings.HasSuffix(got, "»") || strings.Count(got, "«") != 1 {
			t.Fatalf("掩码形态必须是单个整址令牌：%q → %q", s, got)
		}
	}
	// 回放同一文本，令牌必须逐字稳定（顺序无关）。
	replay := []string{"pod «T1»", "pod «T2»", "pod «T3»"}
	for i, s := range []string{"pod 10.0.0.1", "pod 10.0.0.11", "pod 10.0.0.111"} {
		if got := m.Mask(s); got != replay[i] {
			t.Fatalf("同址回放令牌漂移：%q → %q，想要 %q", s, got, replay[i])
		}
	}
}

// TestMaskerRestoreRoundtripAcrossOrder 文本层往返不因调用顺序改变：两轮
// 掩出的文本 Restore 后必须还原全部原文（含长 IP）。
func TestMaskerRestoreRoundtripAcrossOrder(t *testing.T) {
	m := NewMasker()
	first := m.Mask("gw 1.2.3.4")
	second := m.Mask("server 11.2.3.4")
	if got := m.Restore(first); got != "gw 1.2.3.4" {
		t.Fatalf("短 IP 往返失真：%q", got)
	}
	if got := m.Restore(second); got != "server 11.2.3.4" {
		t.Fatalf("长 IP 往返失真（修复前残段 1«T1» 还原成 11.2.3.4 靠巧合）：实得 %q", got)
	}
}

// TestMaskerAddSecretStillBlindReplaced 显式注册串的既有语义不变：AddSecret
// 的串仍参与精确盲替换（含跨调用），动态 IP 豁免只针对 IP 模式注册的原文。
func TestMaskerAddSecretStillBlindReplaced(t *testing.T) {
	m := NewMasker()
	tok := m.AddSecret("secret-instance-name")
	if tok == "" {
		t.Fatal("AddSecret 应返回令牌")
	}
	if got := m.Mask("host secret-instance-name up"); got != "host "+tok+" up" {
		t.Fatalf("显式串应被盲替换，实得 %q", got)
	}
	if got := m.Mask("later secret-instance-name again"); got != "later "+tok+" again" {
		t.Fatalf("显式串跨调用仍应被盲替换，实得 %q", got)
	}
}

// TestMaskerExplicitIPSecretUnaffected 调用方显式把 IP 串注册为 secret 时
// 仍按显式串语义盲替换（文档化的契约，与 RedactSecrets 同款取舍）。
func TestMaskerExplicitIPSecretUnaffected(t *testing.T) {
	m := NewMasker()
	tok := m.AddSecret("1.2.3.4")
	if got := m.Mask("vip 1.2.3.4 up"); got != "vip "+tok+" up" {
		t.Fatalf("显式注册的 IP 串应被盲替换，实得 %q", got)
	}
}
