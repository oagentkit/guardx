package logredact

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// ── 载荷裁剪：只记长度 ──

// TestRedactPayloadsRecordsOriginalLength 是本组用例的核心断言：
// 报出来的长度是**原值**的长度，不是脱敏之后残片的长度。
//
// 为什么这条最要紧：载荷裁剪若排在形状规则之后，135 字节的私钥先被打码成
// "****"，量出来就是 4 —— 审计读到的是「这里有 4 字节的东西」，而实际落盘过
// 135 字节。那是谎报，而且谎在审计唯一要回答的那个问题上。
func TestRedactPayloadsRecordsOriginalLength(t *testing.T) {
	// 这段载荷命中内置的 vendor-token-prefix 规则 ⇒ 若顺序写反，长度会被量成残片。
	payload := "sk-ant-" + strings.Repeat("A", 29)
	in := fmt.Sprintf(`{"content": %q}`, payload)

	got := RedactPayloads(in, "content")
	want := fmt.Sprintf(`{"content": "<%d bytes scrubbed>"}`, len(payload))
	if got != want {
		t.Fatalf("载荷长度应取原值长度（%d），实得 %s", len(payload), got)
	}
	if strings.Contains(got, "sk-ant-") {
		t.Fatalf("载荷内容必须被裁掉，实得 %s", got)
	}

	// 反证：单跑形状规则（Redact）拿到的是残片，长度确实不同 ⇒
	// 这条用例真的在测「顺序」，不是空转。
	only := Redact(in)
	if !strings.Contains(only, "****") {
		t.Fatalf("前提不成立：载荷本应命中形状规则，实得 %s", only)
	}
	if strings.Contains(only, fmt.Sprintf("<%d bytes scrubbed>", len(payload))) {
		t.Fatal("形状规则不该产出长度标记")
	}
}

// TestRedactPayloadsExample 钉住 issue 里给出的形态。
func TestRedactPayloadsExample(t *testing.T) {
	in := `{"content_base64": "` + strings.Repeat("QUJD", 34) + `", "note": "keep me"}`
	got := RedactPayloads(in, "content_base64")
	want := fmt.Sprintf(`{"content_base64": "<136 bytes scrubbed>", "note": "keep me"}`)
	if got != want {
		t.Fatalf("实得 %s", got)
	}
}

// TestRedactPayloadsOnlyTouchesListedFields 钉住「字段名白名单」是白名单。
//
// 刻意不给默认表：哪些字段算载荷是调用方的口径，库里替它猜就等于替它
// 决定什么会落盘。
func TestRedactPayloadsOnlyTouchesListedFields(t *testing.T) {
	in := `{"content": "abcdef", "other": "abcdef"}`
	got := RedactPayloads(in, "content")
	if !strings.Contains(got, `"other": "abcdef"`) {
		t.Fatalf("未列出的字段不得被裁剪，实得 %s", got)
	}
	if !strings.Contains(got, `<6 bytes scrubbed>`) {
		t.Fatalf("列出的字段应被裁剪，实得 %s", got)
	}
}

// TestRedactPayloadsKeepsSurroundingText 钉住「不改写 JSON 结构」。
//
// 打码器改写日志文本的越多，越容易把别的东西改坏（键序、空白、转义）。
// 本入口只替换值那一段，其余逐字节保留。
func TestRedactPayloadsKeepsSurroundingText(t *testing.T) {
	in := `{"b": 1, "a": {"content": "xy"}, "c": [1, 2]}`
	got := RedactPayloads(in, "content")
	want := `{"b": 1, "a": {"content": "<2 bytes scrubbed>"}, "c": [1, 2]}`
	if got != want {
		t.Fatalf("实得 %s", got)
	}
}

// TestRedactPayloadsNonJSONIsUntouched 钉住「非 JSON 文本不炸」。
//
// 工具参数不保证是 JSON（Call.Args 的注释就写着「通常是 JSON 文本」）。
// 认不出来就原样返回，不 panic、不静默改写。
func TestRedactPayloadsNonJSONIsUntouched(t *testing.T) {
	in := "这是一段普通日志：content 不是 JSON"
	if got := RedactPayloads(in, "content"); got != in {
		t.Fatalf("非 JSON 文本应原样返回，实得 %s", got)
	}
}

// TestRedactPayloadsWithKeepsExtensionRules 钉住三段顺序：
// 载荷裁剪 → 内建规则 → 扩展规则。
func TestRedactPayloadsWithKeepsExtensionRules(t *testing.T) {
	in := `{"content": "abcdef", "token": "xyz"}`
	got := RedactPayloadsWith(in, []string{"content"}, []Rule{
		{Name: "ext", Re: mustRe(t, `xyz`), Repl: "***"},
	})
	if !strings.Contains(got, `<6 bytes scrubbed>`) {
		t.Fatalf("载荷应被裁剪，实得 %s", got)
	}
	if !strings.Contains(got, "***") {
		t.Fatalf("扩展规则应生效，实得 %s", got)
	}
}

// TestRedactPayloadsIsIdempotent 钉住「跑两遍得到同一个结果」。
//
// 载荷可能被同一条脱敏链路处理不止一次（多道出口、日志重放）。若第二遍把
// 标记本身又量了一遍，就会报出 "<21 bytes scrubbed>" —— 一个凭空捏造的长度。
func TestRedactPayloadsIsIdempotent(t *testing.T) {
	once := RedactPayloads(`{"content": "abcdef"}`, "content")
	twice := RedactPayloads(once, "content")
	if once != twice {
		t.Fatalf("载荷裁剪应幂等，实得 %s → %s", once, twice)
	}
}

// ── 结构化形态 ──

// TestRedactPayloadValue 钉住结构化入口与文本入口语义一致。
func TestRedactPayloadValue(t *testing.T) {
	in := map[string]any{
		"content": "abcdef",
		"nested":  map[string]any{"body": "xyz"},
		"keep":    "plain",
		"num":     42,
	}
	got := RedactPayloadValue(in, "content", "body")
	m, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("实得 %T", got)
	}
	if m["content"] != "<6 bytes scrubbed>" {
		t.Fatalf("content 应被裁剪，实得 %v", m["content"])
	}
	nested, ok := m["nested"].(map[string]any)
	if !ok {
		t.Fatalf("nested 应保持结构，实得 %v", m["nested"])
	}
	if nested["body"] != "<3 bytes scrubbed>" {
		t.Fatalf("嵌套里的 body 应被裁剪，实得 %v", nested["body"])
	}
	if m["keep"] != "plain" {
		t.Fatalf("未列出的字段应保留，实得 %v", m["keep"])
	}
	if m["num"] != 42 {
		t.Fatalf("非字符串值不应被裁剪，实得 %v", m["num"])
	}
}

// TestRedactPayloadValueAppliesShapeRules 钉住结构化入口也做形状脱敏。
func TestRedactPayloadValueAppliesShapeRules(t *testing.T) {
	in := map[string]any{"dsn": "postgres://user:pass@127.0.0.1:5432/db"}
	got := RedactPayloadValue(in, "content")
	m := got.(map[string]any)
	if !strings.Contains(m["dsn"].(string), "****") {
		t.Fatalf("非载荷字段仍应走形状脱敏，实得 %v", m["dsn"])
	}
}

// ── 热路径构造器 ──

// TestNewPayloadRedactor 钉住构造器与一次性入口等价（且可重复调用）。
func TestNewPayloadRedactor(t *testing.T) {
	f := NewPayloadRedactor([]string{"content"}, nil)
	in := `{"content": "abcdef"}`
	want := RedactPayloads(in, "content")
	if got := f(in); got != want {
		t.Fatalf("构造器应与一次性入口等价，实得 %s vs %s", got, want)
	}
	if got := f(in); got != want {
		t.Fatalf("构造器返回的函数应可重复调用，实得 %s", got)
	}
}

// mustRe 编译正则（测试辅助）。
func mustRe(t *testing.T, expr string) *regexp.Regexp {
	t.Helper()
	return regexp.MustCompile(expr)
}
