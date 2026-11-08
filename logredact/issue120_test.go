package logredact

import (
	"fmt"
	"strings"
	"testing"
)

// 本文件钉 guardx#120 的回归：载荷裁剪原先只认**闭合**的 JSON 字符串——
// 日志落盘前的截断（按字节上限裁、按行切分多行 JSON、框架的 maxMessageLen）
// 把字符串字面量切在半途时，字段正则零命中：既不打码也不告警，残片原文
// 全量落盘。而越长的载荷越容易被截断，缺口方向正好落在最需要保护的一侧。
// 修后：字段正则带「到串尾」兜底分支，未闭合的残片替换成**截断形态**标记
// （"<N bytes scrubbed, truncated>"）——不落原文，且截断本身是告警信号
// （HasTruncatedPayloadMarker）。

// TestTruncatedPayloadScrubbed 截断在一半的字面量：残片必须被裁成截断标记，
// 原文一个子串都不能留。
func TestTruncatedPayloadScrubbed(t *testing.T) {
	content := `line1\nline2\nPRIVATE-DATA-FOLLOWS` // \n 为转义形态（JSON 字面量内的两字符序列）
	in := `{"tool":"write_file","content":"` + content
	got := RedactPayloads(in, "content")
	want := `{"tool":"write_file","content":"<` + fmt.Sprint(1+len(content)) + ` bytes scrubbed, truncated>"`
	if got != want {
		t.Fatalf("截断残片应整体替换为截断标记。\n实得 %s\n想要 %s", got, want)
	}
	if strings.Contains(got, "PRIVATE-DATA-FOLLOWS") {
		t.Fatalf("残片原文不得落盘：%s", got)
	}
	if !HasTruncatedPayloadMarker(got) {
		t.Fatalf("截断形态必须留下可探测的告警信号：%s", got)
	}
}

// TestTruncatedPayloadNoSignalOnClosedForm 闭合形态的对照：行为与既有完全
// 一致（普通标记），且**不**触发截断告警。
func TestTruncatedPayloadNoSignalOnClosedForm(t *testing.T) {
	in := `{"tool":"write_file","content":"line1\nline2\nPRIVATE-DATA-FOLLOWS","ok":true}`
	got := RedactPayloads(in, "content")
	if !strings.Contains(got, "bytes scrubbed>") || strings.Contains(got, "truncated") {
		t.Fatalf("闭合形态应走既有路径产出普通标记，实得 %s", got)
	}
	if HasTruncatedPayloadMarker(got) {
		t.Fatalf("闭合形态不得触发截断告警：%s", got)
	}
}

// TestTruncatedPayloadMultilineEscaped 跨行 \n 转义 + 截断：转义对不得让
// 兜底分支失明（[^"\\]|\\. 的转义对语义对残片同样成立）。
func TestTruncatedPayloadMultilineEscaped(t *testing.T) {
	content := `{"tool":"write_file","content":"第一行\n第二行\n裸载荷-继续`
	got := RedactPayloads(content, "content")
	if !strings.Contains(got, "bytes scrubbed, truncated>") {
		t.Fatalf("跨行转义残片应被截断标记替换，实得 %s", got)
	}
	if strings.Contains(got, "裸载荷") || strings.Contains(got, "第二行") {
		t.Fatalf("残片原文不得落盘：%s", got)
	}
}

// TestTruncatedPayloadMidRune 截断恰好落在多字节字符中间（UTF-8 半个汉字）：
// 残片整体被裁掉，不因非法 UTF-8 序列漏判。
func TestTruncatedPayloadMidRune(t *testing.T) {
	full := "中文载荷内容"
	half := full[:len(full)-1] // 切掉「容」的最后一个字节
	in := `{"content":"` + half
	got := RedactPayloads(in, "content")
	want := `{"content":"<` + fmt.Sprint(1+len(half)) + ` bytes scrubbed, truncated>"`
	if got != want {
		t.Fatalf("多字节截断残片应整体替换。\n实得 %s\n想要 %s", got, want)
	}
	if strings.Contains(got, "中文载荷") {
		t.Fatalf("残片原文不得落盘：%s", got)
	}
}

// TestTruncatedPayloadAfterBackslash 恰好切在反斜杠后面：孤立反斜杠构不成
// 转义对，但同样是原文残片——兜底分支的 `\\?` 就是给这个形态的。
func TestTruncatedPayloadAfterBackslash(t *testing.T) {
	in := `{"content":"abc\` + `\\"` // 内容 "abc\"，闭合引号之后被截——原文残片到 \ 为止
	got := RedactPayloads(in, "content")
	if !strings.Contains(got, "bytes scrubbed, truncated>") {
		t.Fatalf("切在反斜杠后的残片应被裁掉，实得 %s", got)
	}
	if strings.Contains(got, "abc") {
		t.Fatalf("残片原文不得落盘：%s", got)
	}
}

// TestTruncatedPayloadIdempotent 幂等：截断标记落成闭合字符串后，第二遍
// 必须原样保留——「已是标记则原样保留」的判断不能因新形态失效。
func TestTruncatedPayloadIdempotent(t *testing.T) {
	in := `{"content":"载荷残片被截断`
	once := RedactPayloads(in, "content")
	twice := RedactPayloads(once, "content")
	if once != twice {
		t.Fatalf("第二遍必须原样保留标记（幂等）。\n一遍 %s\n两遍 %s", once, twice)
	}
	if !strings.Contains(twice, "bytes scrubbed, truncated>") {
		t.Fatalf("标记形态不应在重放中变化：%s", twice)
	}
}

// TestTruncatedPayloadViaRedactor 高频路径 NewPayloadRedactor（构造期编译
// 正则的快照形态）与即时形态行为一致。
func TestTruncatedPayloadViaRedactor(t *testing.T) {
	r := NewPayloadRedactor([]string{"content", "body"}, nil)
	in := `{"body":"API-BODY-CONTENT-TRUNCATED`
	got := r(in)
	if !strings.Contains(got, "bytes scrubbed, truncated>") || strings.Contains(got, "API-BODY-CONTENT") {
		t.Fatalf("Redactor 路径的截断残片应被裁掉，实得 %s", got)
	}
}

// TestTruncatedAndClosedCoexist 同一段文本里闭合与截断并存：各走各的分支，
// 互不殃及。
func TestTruncatedAndClosedCoexist(t *testing.T) {
	in := `{"note":"keep","content":"TRUNCATED-PAYLOAD-REMAINDER`
	got := RedactPayloads(in, "content")
	if !strings.Contains(got, `"note":"keep"`) {
		t.Fatalf("白名单外的字段不得被裁：%s", got)
	}
	if !strings.Contains(got, "bytes scrubbed, truncated>") || strings.Contains(got, "TRUNCATED-PAYLOAD") {
		t.Fatalf("截断残片应被裁掉：%s", got)
	}
}

// TestTruncatedSurvivesBuiltinRules 截断标记必须活着穿过内建形状规则
// （RedactPayloads 的三段顺序：载荷裁剪 → 内建规则 → 扩展规则）。
func TestTruncatedSurvivesBuiltinRules(t *testing.T) {
	in := `{"content":"sk-ant-" + string` // 残片内含形状规则会命中的前缀
	in = `{"content":"sk-ant-` + strings.Repeat("A", 29)
	got := RedactPayloads(in, "content")
	if !strings.Contains(got, "bytes scrubbed, truncated>") {
		t.Fatalf("截断标记应穿过形状规则原样保留，实得 %s", got)
	}
	if strings.Contains(got, "sk-ant-") || strings.Contains(got, "AAAA") {
		t.Fatalf("残片原文不得落盘：%s", got)
	}
}

// TestHasTruncatedPayloadMarkerOnRawText 语义边界：对未脱敏的原文
// 恒返回 false——先裁剪、后探测。
func TestHasTruncatedPayloadMarkerOnRawText(t *testing.T) {
	if HasTruncatedPayloadMarker(`{"content":"纯原文没有标记"}`) {
		t.Fatal("未脱敏原文不得误报截断标记")
	}
	if HasTruncatedPayloadMarker("") {
		t.Fatal("空文本不得误报")
	}
}
