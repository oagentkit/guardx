package logredact

import (
	"strings"
	"testing"
)

// 本文件钉 guardx#121 的回归：截断兜底规则的 $ 锚点原先只认「整段文本末尾」
//（RE2 无 (?m) 时 $ 的语义）。日志 shipper 按行截断（Loki/Fluentd 行上限、
// head -c、终端裁剪）后**后面还有行**是常态——彼时 $ 不在该行末尾，截断
// 兜底规则失配，闭合规则又需要收尾引号、裸值规则不能从开引号起步，三条路
// 全堵死，password/token/api_key 的整值原文全量泄漏。修后：兜底规则改
// (?m)$（行尾锚）；[^"\n]* 本就不跨行，值匹配仍锁在单行内。

// TestTruncatedCredentialMaskedPerLine issue 实测复现场景：截断点在行尾、
// 后面还有行——双引号形态必须整值掩掉。
func TestTruncatedCredentialMaskedPerLine(t *testing.T) {
	in := "{\"event\":\"api_call\",\"password\": \"hunter2-secret-tail\nlevel=info msg=\"next line follows\""
	got := Redact(in)
	if strings.Contains(got, "hunter2") {
		t.Fatalf("逐行截断形态凭据原文泄漏（#121）：\n%s", got)
	}
	if !strings.Contains(got, `"password": "****`) {
		t.Fatalf("截断值应掩成保开引号的截断形态，实得：\n%s", got)
	}
	if !strings.Contains(got, `msg="next line follows"`) {
		t.Fatalf("后续行不得被吞掉，实得：\n%s", got)
	}
}

// TestTruncatedCredentialMaskedPerLineSingleQuote 单引号形态同泄漏，同修。
func TestTruncatedCredentialMaskedPerLineSingleQuote(t *testing.T) {
	in := "password: 'hunter2-secret-tail\nlevel=info msg=\"next line follows\""
	got := Redact(in)
	if strings.Contains(got, "hunter2") {
		t.Fatalf("单引号逐行截断形态凭据原文泄漏（#121）：\n%s", got)
	}
	if !strings.Contains(got, "password: '****") {
		t.Fatalf("单引号截断值应掩成 '**** 形态，实得：\n%s", got)
	}
}

// TestTruncatedCredentialMaskedPerLineBareJSON 裸 JSON 形态（键值紧邻、值
// 截断在行尾）同泄漏，同修。
func TestTruncatedCredentialMaskedPerLineBareJSON(t *testing.T) {
	in := `{"api_key":"sk-abc123secret-tail` + "\n" + `level=info msg="next"`
	got := Redact(in)
	if strings.Contains(got, "sk-abc123secret-tail") {
		t.Fatalf("裸 JSON 逐行截断形态凭据原文泄漏（#121）：\n%s", got)
	}
}

// TestTruncatedCredentialPerLineIdempotent 幂等回归（issue 修法要求）：对
// 已掩文本二次 Redact 必须不变——掩码行尾 `"****` 二次命中替换为自身，
// 不得滚雪球出 `""****` 一类残形。
func TestTruncatedCredentialPerLineIdempotent(t *testing.T) {
	in := "{\"event\":\"api_call\",\"password\": \"hunter2-secret-tail\nlevel=info msg=\"next line follows\""
	once := Redact(in)
	twice := Redact(once)
	if once != twice {
		t.Fatalf("二次 Redact 必须幂等。\n一次: %q\n二次: %q", once, twice)
	}
}

// TestClosedValueOnItsOwnLineStillClosed 闭合值独占一行（多行 JSON 日志
// 常态）不受 (?m) 影响：闭引号规则先行命中，截断兜底不得把闭合形态改成
// 未闭合残形。
func TestClosedValueOnItsOwnLineStillClosed(t *testing.T) {
	in := "{\n  \"password\": \"hunter2\",\n  \"level\": 3\n}"
	got := Redact(in)
	want := "{\n  \"password\": \"****\",\n  \"level\": 3\n}"
	if got != want {
		t.Fatalf("闭合值应保持闭合掩码形态。\n实得 %q\n想要 %q", got, want)
	}
	if Redact(got) != want {
		t.Fatalf("闭合掩码形态二次 Redact 必须幂等，实得 %q", Redact(got))
	}
}

// TestTruncatedAtTextEndStillMasked 对照组（#50 原场景）：截断值恰在整段
// 末尾——既有行为必须保持。
func TestTruncatedAtTextEndStillMasked(t *testing.T) {
	in := `{"password": "hunter2-tail`
	got := Redact(in)
	if strings.Contains(got, "hunter2") {
		t.Fatalf("整段末尾截断形态原文泄漏：\n%s", got)
	}
	if !strings.Contains(got, `"password": "****`) {
		t.Fatalf("截断值应掩成 \"**** 形态，实得：\n%s", got)
	}
}
