// guardx#187 裸 userinfo 形态回归：无 scheme 的 `user:pass@host`（DSN/连接串
// 形态）此前按 url-embedded-credential 的 `:scheme//` 文法锚定全链路不命中，
// 凭据整串落盘。本单新增 bare-userinfo-credential 规则，并把误伤面（时间戳 /
// 邮件变体 / 路径内冒号）的裁决钉成对照表。
package logredact

import (
	"regexp"
	"strings"
	"testing"
)

// TestIssue187BareUserinfoHit 裸形态命中面：每条给出「修复前泄漏 → 修复后
// 中和」的精确对照（首条即 issue 复现样本）。
func TestIssue187BareUserinfoHit(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		// issue 复现样本：DSN/连接串，无 ://。
		{"connection=user:secretpw@10.0.0.9:5432/app", "connection=user:****@10.0.0.9:5432/app"},
		// #179 同款口径：密码段允许 /（裸面同样允许——终止符是 @）。
		{"connection=user:p/ass@host:5432/db", "connection=user:****@host:5432/db"},
		// 多段密码（user:pa:ss@）：密码段 [^\s@]+ 允许 :，整段掩。
		{"admin:pa:ss@db.internal", "admin:****@db.internal"},
		// 引号边界（JSON 字符串值里的裸连接串）。
		{`{"connection":"user:pass@host/db"}`, `{"connection":"user:****@host/db"}`},
		// 空白边界 + 端口/路径在 @ 之后原样保留。
		{"peer user:pass@host:5432/db tail", "peer user:****@host:5432/db tail"},
		// 同行两条裸 userinfo（空白分隔，各自有边界）都掩。
		{"user:pass@host and admin:pw@host2", "user:****@host and admin:****@host2"},
	} {
		if got := Redact(c.in); got != c.want {
			t.Errorf("裸形态应命中: %q -> got %q, want %q", c.in, got, c.want)
		}
	}
	// 幂等：掩码形态二次过规则不变。
	masked := "connection=user:****@10.0.0.9:5432/app"
	if out := Redact(masked); out != masked {
		t.Errorf("二次脱敏应幂等: %q -> %q", masked, out)
	}
	// 结构化路径的字符串叶子同一命中。
	if got := RedactValue(map[string]any{"conn": "user:pass@host/db"}); got.(map[string]any)["conn"] != "user:****@host/db" {
		t.Errorf("结构化叶子应同口径: %v", got)
	}
}

// TestIssue187BareUserinfoFalsePositives 误伤面对照表（issue 要求的验收面）：
// 下列样本**全部原样保留**（或按既有规则的既有行为处理），逐条标注豁免机制。
func TestIssue187BareUserinfoFalsePositives(t *testing.T) {
	for _, in := range []string{
		// 时间戳：用户段首字符 [A-Za-z] 锚定，数字开头整体失配。
		"12:34@host",
		"2026-11-14T12:34:56Z",
		"scheduled at 12:34@host",
		// 邮件变体：纯邮箱无冒号（形态不失配即不命中）。
		"alice@example.com",
		// 邮件变体：mailto: 的冒号后是邮箱本地部——Guard 豁免（RFC 6068）。
		"mailto:alice@example.com",
		"MAILTO:Alice@Example.com",
		// 邮件变体：尖括号地址形态（Message-ID 家族）——Guard 豁免。
		"Message-ID:<a1b2c3.12345@mail.example.com>",
		// 路径内冒号：冒号后无凭据体（pass 段为空）不失配；issue 样本原样保留。
		"a/b:c@",
		// scheme URL 的既有行为保持：文法规则先掩，本规则不吞 URL 结构
		// （Guard 的 `//` 豁免 + 左边界排除 / 双保险）。
	} {
		if out := Redact(in); out != in {
			t.Errorf("误伤面样本应原样保留: %q -> %q", in, out)
		}
	}
	for _, c := range []struct{ in, want string }{
		{"https://user:p/ass@host/db", "https://user:****@host/db"},
		{"redis://:secretpw@host:6379/0", "redis://:****@host:6379/0"},
		// 路径中段嵌入完整凭据样式（冒号后有体）照样掩——over-mask 方向：
		// 边界字符回填重构原文，凭据体掩掉、结构形态不变。
		{"GET /objects/user:token@cdn.example.com HTTP/1.1", "GET /objects/user:****@cdn.example.com HTTP/1.1"},
	} {
		if got := Redact(c.in); got != c.want {
			t.Errorf("scheme URL 结构必须保住: %q -> got %q, want %q", c.in, got, c.want)
		}
	}
	// 纯用户名无密码（git clone 最高频 URL）照旧不掩——用户名不是凭据。
	if got := Redact("ssh://git@github.com/oagentkit/guardx.git"); got != "ssh://git@github.com/oagentkit/guardx.git" {
		t.Errorf("纯用户名形态应保持不掩: %q", got)
	}
}

// TestIssue187ConnectionKeyAdjudication kv 词表裁决（issue 列议项）：connection
// 刻意**不**收凭证词表——中性遥测词（connection=5 / connection_timeout /
// connections 池指标），收词表整值打码 = 计量面数据损坏（#52 同款）。凭据面
// 由裸 userinfo 规则按**值形态**兜住，与键名无关。
func TestIssue187ConnectionKeyAdjudication(t *testing.T) {
	for _, in := range []string{
		"connection=5",
		"connection_timeout=30ms",
		"connections=42",
	} {
		if out := Redact(in); out != in {
			t.Errorf("中性 connection 键不得误掩: %q -> %q", in, out)
		}
	}
	// 同键的凭据形态按值形态命中（键名无关）。
	if got := Redact("connection=user:secretpw@10.0.0.9:5432/app"); strings.Contains(got, "secretpw") {
		t.Errorf("凭据值形态必须命中: %q", got)
	}
	// Guard 是公开规则能力：扩展规则也能表达上下文豁免（RE2 无环视的公开出口）。
	keep := Rule{
		Name:  "keep-markdown-links",
		Re:    regexp.MustCompile(`\[x\]\(secret-[a-z0-9]+\)`),
		Repl:  "[x](****)",
		Guard: func(match string) bool { return !strings.Contains(match, "secret-keep") },
	}
	if out := RedactWith("[x](secret-keep123)", []Rule{keep}); out != "[x](secret-keep123)" {
		t.Errorf("Guard 返回 false 的命中应原样保留: %q", out)
	}
	if out := RedactWith("[x](secret-drop789)", []Rule{keep}); out != "[x](****)" {
		t.Errorf("Guard 返回 true 的命中应正常替换: %q", out)
	}
}
