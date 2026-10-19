// Package logredact 日志/审计载荷凭据脱敏：连接串/URL/头中的凭据在落日志前模式化打码。
// 与 fence（Markdown/HTML 注入卫生）正交——本包打码凭据。
//
// 规则表是**公开且可组合**的：Rules() 给出内置表副本，RedactWith / NewRedactor
// 接受调用方自己的扩展规则。下游各家的凭据形态不一样（厂商前缀族、裸 hex、
// 任意 scheme 的 URL…），把表关在包内就等于逼下游**重写一整份脱敏器**，
// 或在后面串第二道——两道顺序敏感、掩码风格还不一致。
package logredact

import (
	"regexp"
	"sort"
	"strings"
)

// MaskStyle 命中后的替换方式。
type MaskStyle int

const (
	// MaskStyleLiteral 按 Repl 字面替换（支持 $1 引用）。内置规则用它**保留结构**：
	// scheme、用户名、键名留着，只有凭据体变成 ****——处置后的文本仍能看出
	// 「是哪一条凭据」。这是默认档。
	MaskStyleLiteral MaskStyle = iota
	// MaskStyleHint 保定位线索的不可逆掩码：保留首尾各 Keep 个字符。
	// 用于「全量打码会让人认不出是哪一条凭据」的场景。
	//
	// 与 MaskStyleLiteral 是**不同档**，不是替代关系：前者给的是「认不出」，
	// 后者给的是「认得出但不还原」。
	MaskStyleHint
)

// Rule 一条脱敏规则。
//
// 命中后按 Style 替换：
//
//	MaskStyleLiteral —— 整段替换为 Repl（字面，支持 $1/$2 引用）；
//	MaskStyleHint    —— 整段替换为保留首尾各 Keep 字符的不可逆掩码（Repl 被忽略）。
//
// 规则表按声明顺序应用；**同一条规则内的多个匹配**由 regexp 一次性替换。
type Rule struct {
	// Name 规则名（诊断用：扩展规则出错时要能指出是哪一条）。
	Name string
	// Re 命中模式。nil 的规则会被跳过（不 panic）。
	Re *regexp.Regexp
	// Repl 字面替换串，支持 $1 引用。Style=MaskStyleHint 时被忽略。
	Repl string
	// Style 替换方式，默认 MaskStyleLiteral。
	Style MaskStyle
	// Keep Style=MaskStyleHint 时保留的首尾字符数（<=0 取 DefaultHintKeep）。
	Keep int
	// Group Style=MaskStyleHint 时，掩码作用在**第几个捕获组**（1 起）；0 = 整段匹配。
	//
	// 默认 0（整段）有个陷阱：规则的匹配范围里若含上下文（如 "password=xxx"），
	// 整段掩码保留的尾部 4 个字符**就是凭据的一部分**——那不是定位线索，是泄露。
	// 所以凭据类规则应当用捕获组圈出凭据本体，再把 Group 指过去。
	Group int
}

// builtinRules 内置规则表（顺序即应用顺序）。
//
// ⚠️ 顺序是语义的一部分：靠前的规则更精确（能定位到凭据体），
// 靠后的更宽（整段吞掉）。靠后规则看到的是「已被精确处理过」的文本。
var builtinRules = []Rule{
	{
		Name: "url-embedded-credential",
		Re:   regexp.MustCompile(`(?i)\b(nats|postgres|postgresql|mysql|mongodb\+srv|mongodb|http|https|redis|amqps|amqp)://([^\s:@/]+):([^\s@/]+)@`),
		Repl: "$1://$2:****@",
	},
	{
		// key 单独留紧邻形态（[=:] 后无空白）——"user-keynote" 类散文防误伤
		Name: "key-value",
		Re:   regexp.MustCompile(`(?i)\bkey[=:]["']?([^\s&'"]+)`),
		Repl: "key=****",
	},
	{
		// 凭证词键值对（容忍 ": " 空格形态——YAML/缩进 JSON 日志最高频的
		// `password: xxx` 形态；第九轮审计：password/token 此前漏在紧邻词表，
		// 冒号后带空格即整体漏网）
		Name: "credential-kv",
		Re:   regexp.MustCompile(`(?i)([A-Za-z0-9]*(?:[-_][A-Za-z0-9]*)*(?:token|secret|password|passwd|passphrase|api_?key|access_?key|private[-_]?key|secret[-_]?key|client[-_]?key|kubeconfig))["']?\s*[=:]\s*(?:"[^"\n&]*"|'[^'\n&]*'|[^\s&'"]+)`),
		Repl: "$1=****",
	},
	{
		// PEM 私钥整段打码（载荷/日志防泄漏的最后兜底）
		Name: "pem-private-key",
		Re:   regexp.MustCompile(`(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`),
		Repl: "----PRIVATE KEY ****",
	},
	{
		// 第二条为截断兜底——日志超长截断落在 PEM 中段时无 END，
		// 私钥体无前缀特征会原文泄漏
		Name: "pem-private-key-truncated",
		Re:   regexp.MustCompile(`(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*$`),
		Repl: "----PRIVATE KEY ****（截断）",
	},
	{
		// Authorization 头：值吃到行尾——第九轮审计 C 级修复：\S+ 只吃 scheme
		// 名（Basic/Bearer），凭据本体残留且后续 Bearer 规则失去锚点兜不住
		Name: "authorization-header",
		Re:   regexp.MustCompile(`(?i)(authorization|www-authenticate)\s*[:=]\s*[^\r\n]*`),
		Repl: "$1=****",
	},
	{
		Name: "bearer-token",
		Re:   regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9._~+/=-]+`),
		Repl: "Bearer ****",
	},
	{
		// 平台 API token 特征前缀（裸 token 不带 key= 形态出现在散文/URL 路径时的兜底；
		// 键值对形态已由上方规则先行打码，本组只负责无键形态）。
		Name: "vendor-token-prefix",
		Re:   regexp.MustCompile(`\b(sk-ant-[A-Za-z0-9_-]{16,}|sk-(?:proj|svcacct|None)-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b`),
		Repl: "****",
	},
	{
		// JWT（三段式， eyJ 头 + 两段 base64url）：出现在日志散文里的裸 JWT。
		Name: "jwt",
		Re:   regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`),
		Repl: "****JWT****",
	},
}

// Rules 返回内置规则表的**副本**。
//
// 返回副本而不是共享切片：调用方要能自由改自己的表（追加规则、改顺序），
// 共享切片的话改到一半就污染了全进程的内置规则——而这份表是所有日志出口共用的。
// 规则里的 *regexp.Regexp 是不可变的，共享指针是安全的。
func Rules() []Rule {
	out := make([]Rule, len(builtinRules))
	copy(out, builtinRules)
	return out
}

// Redact 返回打码后的文本（无命中原样返回）。
//
// 等价于 RedactWith(s, nil)：只跑内置规则。
func Redact(s string) string {
	return RedactWith(s, nil)
}

// RedactWith 用内置规则 + 扩展规则脱敏。
//
// **应用顺序：先内置、后扩展**（每组内部按声明顺序）。
//
// 为什么是这个顺序：内置规则的打码**保留结构**（"$1://$2:****@" —— scheme 与
// 用户名留着，只有凭据体被替换），它对同一段文本的定位比扩展规则精确。
// 先跑内置，扩展规则面对的就是「已经打过码」的文本，既不会把内置已处理的凭据
// 再脱一次（幂等），也不会让扩展的粗规则先吃掉内置能精确定位的那部分。
//
// 扩展规则里 Re 为 nil 的会被跳过（不 panic）——扩展表是调用方给的，
// 一条写错的规则不该让整条脱敏链路崩掉。
func RedactWith(s string, extra []Rule) string {
	for _, r := range builtinRules {
		s = applyRule(s, r)
	}
	for _, r := range extra {
		s = applyRule(s, r)
	}
	return s
}

// NewRedactor 返回一个可复用的脱敏函数（内置规则 + 扩展规则）。
//
// 规则表在构造时**快照**一次：调用方之后改自己的切片，不影响已构造的脱敏器。
// 返回的函数是并发安全的（只读规则表，不改共享状态）。
//
// 高频路径（日志热路径、每条 tool_call 都过一遍）用这个，别每次重建规则表。
func NewRedactor(extra []Rule) func(string) string {
	snapshot := make([]Rule, 0, len(builtinRules)+len(extra))
	snapshot = append(snapshot, builtinRules...)
	snapshot = append(snapshot, extra...)
	return func(s string) string {
		for _, r := range snapshot {
			s = applyRule(s, r)
		}
		return s
	}
}

// applyRule 按单条规则替换。
func applyRule(s string, r Rule) string {
	if r.Re == nil {
		return s
	}
	if r.Style == MaskStyleHint {
		return r.Re.ReplaceAllStringFunc(s, func(m string) string {
			return hintMatch(r, m)
		})
	}
	return r.Re.ReplaceAllString(s, r.Repl)
}

// hintMatch 对单次匹配做「保定位线索」掩码。
//
// Group>0 时只掩码第 Group 个捕获组，匹配其余部分原样保留——
// 这样「key=凭据」这类规则的线索留在键名上，**不会把凭据的尾巴当成线索留下**。
func hintMatch(r Rule, m string) string {
	if r.Group <= 0 {
		return MaskHintWith(m, r.Keep)
	}
	idx := r.Re.FindStringSubmatchIndex(m)
	if r.Group >= len(idx)/2 {
		return MaskHintWith(m, r.Keep)
	}
	lo, hi := idx[2*r.Group], idx[2*r.Group+1]
	if lo < 0 || hi < 0 {
		// 该组没参与匹配（可选组未命中）→ 整段兜底
		return MaskHintWith(m, r.Keep)
	}
	return m[:lo] + MaskHintWith(m[lo:hi], r.Keep) + m[hi:]
}

// RedactSecrets 抹除调用方已知的确切秘密（clone URL 内嵌 token、动态签发的临时
// 凭据等）：与模式化 Redact 互补——Redact 靠规则打码未知形态的凭据，本函数抹除
// 已知值。与 Masker 相反，高敏感秘密不做令牌、不回填（Masker 只收低敏感拓扑标识）。
// 长秘密优先替换（防短串是长串前缀时留下尾段泄漏），空串忽略。
func RedactSecrets(s string, secrets ...string) string {
	sorted := append([]string(nil), secrets...)
	sort.Slice(sorted, func(i, j int) bool { return len(sorted[i]) > len(sorted[j]) })
	for _, sec := range sorted {
		if sec == "" {
			continue
		}
		s = strings.ReplaceAll(s, sec, "***")
	}
	return s
}

// RedactValue 递归脱敏任意 JSON 形态值：map/slice 逐字段下探，字符串过 Redact，其余原样。
// 事件载荷入库前的统一出口——tool_call 参数与 tool_result 文本常含连接串、webhook key、Bearer 头。
func RedactValue(v any) any {
	switch t := v.(type) {
	case string:
		return Redact(t)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, vv := range t {
			out[k] = RedactValue(vv)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, vv := range t {
			out[i] = RedactValue(vv)
		}
		return out
	default:
		return v
	}
}
