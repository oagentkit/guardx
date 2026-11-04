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
// credentialSuffix 凭证词键的后缀词表（snake/kebab 复合键 + camelCase 拼接
// 共用）：前缀允许任意字母数字与 [-_] 分隔段，后缀锚定键的末词。
//
// 覆盖口径（oagentkit/guardx#45）：pwd/pass 这类**常见缩写**与 token/secret/
// password/key 的复数形态必须命中——值模式脱敏的承诺是「键表内的键，值必被
// 打码」，键表覆盖面就是这个承诺的边界，缺一个常见缩写 = 该形态静默泄漏。
// 已知代价：bypass/surpass 这类以 pass 结尾的普通词会被误伤（over-mask 是
// 安全方向的错，漏 mask 才是事故）。
const credentialSuffix = `(?:tokens?|secrets?|pass(?:words?|wds?|es)?|pwds?|passphrases?|api_?keys?|access_?keys?|private[-_]?keys?|secret[-_]?keys?|client[-_]?keys?|auths?|kubeconfig)`

// credentialKeyPart 凭证词键的完整匹配段：复合前缀 + 末词后缀。
const credentialKeyPart = `([A-Za-z0-9]*(?:[-_][A-Za-z0-9]*)*` + credentialSuffix + `)`

// bareValue 裸值形态：可选的 scheme 前缀（Bearer/Basic + 空白）连同凭据体
// 一起算作值——bearer 组规则先行打码后留下 `key=Bearer ****`，kv 规则若只吃
// `Bearer` 一词会留下孤儿掩码段；整体吞掉后输出收敛为单段 `key=****`。
const bareValue = `((?:(?:Bearer|Basic)\s+)?[^\s&'"]+)`

// kvSeparator 键与值之间的分隔段（含键自身的闭引号）：捕获保留，替换时原样
// 回填——「"key": "v"」打码后仍是「"key": "****"」，JSON 行的结构不再被
// 打码动作本身破坏（oagentkit/guardx#44：此前 Repl 把分隔段吞成 `=`，冒号
// 变等号、引号丢失，日志采集侧的 JSON 解析器整行降级）。
const kvSeparator = `(["']?\s*[=:]\s*)`

var builtinRules = []Rule{
	{
		Name: "url-embedded-credential",
		Re:   regexp.MustCompile(`(?i)\b(nats|postgres|postgresql|mysql|mongodb\+srv|mongodb|http|https|redis|amqps|amqp)://([^\s:@/]+):([^\s@/]+)@`),
		Repl: "$1://$2:****@",
	},
	{
		// bearer/jwt/vendor 三组锚定**凭据体自身**（Bearer 后的 token 串、eyJ
		// 三段式、平台特征前缀）——按「精确在前、宽泛在后」的总原则排在键值对
		// 之前：kv 规则吃掉 `auth=Bearer` 的键值形态后，Bearer/JWT 锚点就没了
		// （实测回归：auth 入词表后 `auth=Bearer <JWT>` 的 JWT 反而漏网）。
		Name: "bearer-token",
		Re:   regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9._~+/=-]+`),
		Repl: "Bearer ****",
	},
	{
		// JWT（三段式， eyJ 头 + 两段 base64url）：出现在日志散文里的裸 JWT。
		Name: "jwt",
		Re:   regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`),
		Repl: "****JWT****",
	},
	{
		// 平台 API token 特征前缀（裸 token 不带 key= 形态出现在散文/URL 路径时的兜底；
		// 带键形态由后方的键值对规则整值打码，本组先行命中不冲突——kv 规则
		// 对 `key=****` 的二次替换是幂等的）。
		Name: "vendor-token-prefix",
		Re:   regexp.MustCompile(`\b(sk-ant-[A-Za-z0-9_-]{16,}|sk-(?:proj|svcacct|None)-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b`),
		Repl: "****",
	},
	{
		// key 单独留紧邻形态——"user-keynote" 类散文防误伤（\b 后首字符不是
		// [=:'] 即不命中）。键值对按**值形态拆三条**（双引号/单引号/裸）：打码
		// 保留原分隔符与引号形态——JSON 行打码后仍是合法 JSON、YAML 保持
		// `key: '****'` 原貌；引号形态各自回填还能避免「单引号 kv 内嵌在
		// JSON 字符串值里」时向外交错注入双引号（oagentkit/guardx#44：此前
		// Repl 把分隔段吞成 `=`，冒号变等号、引号丢失，采集侧 JSON 解析器
		// 整行降级）。Repl 按形态硬编码引号是刻意为之——单条正则条件回填
		// 引号需要 backreference，ReplaceAll 的 $N 语义做不到。
		Name: "key-value-double-quoted",
		Re:   regexp.MustCompile(`(?i)\b(key)` + kvSeparator + `("[^"\n]*")`),
		Repl: `$1$2"****"`,
	},
	{
		Name: "key-value-single-quoted",
		Re:   regexp.MustCompile(`(?i)\b(key)` + kvSeparator + `('[^'\n]*')`),
		Repl: `$1$2'****'`,
	},
	{
		Name: "key-value",
		Re:   regexp.MustCompile(`(?i)\b(key)` + kvSeparator + bareValue),
		Repl: `$1$2****`,
	},
	{
		// 凭证词键值对（容忍 ": " 空格形态——YAML/缩进 JSON 日志最高频的
		// `password: xxx` 形态；第九轮审计：password/token 此前漏在紧邻词表，
		// 冒号后带空格即整体漏网）。值形态三拆的理由见 key-value 组。
		Name: "credential-kv-double-quoted",
		Re:   regexp.MustCompile(`(?i)` + credentialKeyPart + kvSeparator + `("[^"\n]*")`),
		Repl: `$1$2"****"`,
	},
	{
		Name: "credential-kv-single-quoted",
		Re:   regexp.MustCompile(`(?i)` + credentialKeyPart + kvSeparator + `('[^'\n]*')`),
		Repl: `$1$2'****'`,
	},
	{
		Name: "credential-kv",
		Re:   regexp.MustCompile(`(?i)` + credentialKeyPart + kvSeparator + bareValue),
		Repl: `$1$2****`,
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
		// Authorization 头：引号值两条保形（JSON 行里的 `"authorization": "v"`
		// 打码后行内其余部分原样保留）；裸值仍吃到行尾——第九轮审计 C 级修复：
		// \S+ 只吃 scheme 名（Basic/Bearer），凭据本体残留且后续 Bearer 规则
		// 失去锚点兜不住（Bearer 组现已在键值对之前，锚点保护双保险）。
		// 裸值吃行尾的代价是散文内嵌形态会把行尾一并吞掉——JSON 键值形态
		// 已被前两条引号规则截住，不受影响。
		Name: "authorization-header-double-quoted",
		Re:   regexp.MustCompile(`(?i)(authorization|www-authenticate)` + kvSeparator + `("[^"\n]*")`),
		Repl: `$1$2"****"`,
	},
	{
		Name: "authorization-header-single-quoted",
		Re:   regexp.MustCompile(`(?i)(authorization|www-authenticate)` + kvSeparator + `('[^'\n]*')`),
		Repl: `$1$2'****'`,
	},
	{
		Name: "authorization-header",
		Re:   regexp.MustCompile(`(?i)(authorization|www-authenticate)\s*[:=]\s*[^\r\n]*`),
		Repl: "$1=****",
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

// RedactValue 递归脱敏任意 JSON 形态值：凭证词键的整值打码（键感知，
// jsonredact.go），其余 map/slice 逐字段下探，字符串过 Redact，其余原样。
// 事件载荷入库前的统一出口——tool_call 参数与 tool_result 文本常含连接串、
// webhook key、Bearer 头。
//
// ⚠️ v0.14.0 起键感知（oagentkit/guardx#44 同源缺陷）：此前只有字符串值过
// 文本规则——而文本规则靠 `password=xxx` 的**键值形态**定位，解码后的值
// "abc123" 早已失去键上下文 ⇒ `{"password": "abc123"}` 原样透传（泄漏）。
// 键感知打码补上这层：键名命中凭证词表（jsonCredentialKeyRe）即整值打码。
func RedactValue(v any) any {
	return redactWalk(v, nil)
}
