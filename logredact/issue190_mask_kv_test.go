package logredact

import (
	"strings"
	"testing"
)

// guardx#190：credential-kv 行尾变体对外来掩码 «kind:****» 二次掩码，
// 吞掉收尾 »（括号不配对）——掩码区豁免后必须幂等原样。
func TestCredentialKvExemptsMaskRegion(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string // 空 = 期望原样不变
	}{
		{"stringx 外来掩码整行", "«secret-assignment:****»", ""},
		{"掩码在行中", `log level=info payload=«private-key-block:****»`, ""},
		{"掩码键含 token 词", "auth «known-token-prefix:****» done", ""},
		{"正常裸凭证照常掩", "password: horse battery", "password: horse battery"}, // 见下方专门断言
		{"法式引号带空格照常掩", "« password: hunter2 »", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := Redact(tc.in)
			switch tc.name {
			case "正常裸凭证照常掩":
				// kvSeparator 保留分隔空格（$2 原样回填）⇒ 输出 "password: ****"
				if !strings.Contains(out, "password:") || !strings.Contains(out, "****") {
					t.Fatalf("裸凭证应被掩: in=%q out=%q", tc.in, out)
				}
				if strings.Contains(out, "horse") {
					t.Fatalf("口令原文泄漏: out=%q", out)
				}
			case "法式引号带空格照常掩":
				// « 后有空格 ⇒ 边界不是 « ⇒ 不豁免（不为保括号开泄漏口）。
				// 掩完 » 是否残留取决于行尾变体的吞并范围——关键是 hunter2 必须没泄漏。
				if strings.Contains(out, "hunter2") {
					t.Fatalf("法式引号内的口令不得泄漏: out=%q", out)
				}
			default:
				if out != tc.in {
					t.Fatalf("掩码区应幂等原样: in=%q out=%q", tc.in, out)
				}
				if strings.Count(out, "«") != strings.Count(out, "»") {
					t.Fatalf("掩码括号必须配对: out=%q", out)
				}
			}
		})
	}
}
