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
	//
	// 组捕获失败（Group 越界、可选组未参与匹配）时回退**全量打码**而非整段
	// hint——整段 hint 的尾 4 字符落在凭据上，正是本注释警告的陷阱本身
	// （guardx#69）：宁可丢线索，不留尾巴。
	Group int
}

// builtinRules 内置规则表（顺序即应用顺序）。
//
// ⚠️ 顺序是语义的一部分：靠前的规则更精确（能定位到凭据体），
// 靠后的更宽（整段吞掉）。靠后规则看到的是「已被精确处理过」的文本。
// credentialSuffixGeneral 凭证词键的后缀词表（snake/kebab 复合键 + camelCase
// 拼接共用）：前缀允许任意字母数字与 [-_] 分隔段，后缀锚定键的末词。
// token 单独拆出（credentialKeyToken，见其注释）。
//
// 覆盖口径（oagentkit/guardx#45）：pwd/pass 这类**常见缩写**与 secret/
// password/key 的复数形态必须命中——值模式脱敏的承诺是「键表内的键，值必被
// 打码」，键表覆盖面就是这个承诺的边界，缺一个常见缩写 = 该形态静默泄漏。
// 已知代价：bypass/surpass 这类以 pass 结尾的普通词会被误伤（over-mask 是
// 安全方向的错，漏 mask 才是事故）。
const credentialSuffixGeneral = `(?:secrets?|pass(?:words?|wds?|es)?|pwds?|passphrases?|api_?keys?|access_?keys?|private[-_]?keys?|secret[-_]?keys?|client[-_]?keys?|auths?|kubeconfig)`

// credTokenPrefix 凭证语义的 token 复合前缀段（v0.18.1 收窄，oagentkit/guardx#52）：
// 复数 tokens 只在「凭证前缀段 + tokens」时命中。
//
// 为什么收窄：旧词表的 tokens? 后缀把 LLM usage 计量字段（prompt_tokens /
// completion_tokens / total_tokens / cached_tokens / reasoning_tokens——结构化
// 日志里的高频合法键）整值打码，事件载荷里用量被毁 = 计价/评测/配额读到掩码
// （数据损坏方向的静默错，比漏打更坏）。计量字段恒为**复数**且前缀无凭证语义
// ⇒ 复数收窄、单数保持全量命中（*_token 单数形态几乎都是凭证，裸 token 亦然）。
// 裸复数 tokens（整键就是 "tokens"）保持命中：token 池/令牌数组是合理凭证形态。
const credTokenPrefix = `(?:access|refresh|auth|api|session|bearer|id|client|device|reset|invite|registration|verification|github|oauth|bot|service|user|app|personal|install|identity|login|sign(?:in|out|up)?|one[_-]?time|activation|confirm|magic|share|webhook|callback|license|csrf|xsrf|secret|admin|sudo|temp)`

// credentialKeyPart 凭证词键的完整匹配段（kv 规则共用，单捕获组 = 键名）：
// 非 token 词走「复合前缀 + 末词后缀」，token 按 credTokenPrefix 注释的
// 收窄口径单列一支。
const credentialKeyPart = `((?:[A-Za-z0-9]*(?:[-_][A-Za-z0-9]*)*` + credentialSuffixGeneral + `)|(?:[A-Za-z0-9]+(?:[-_][A-Za-z0-9]+)*[-_])?` + credTokenPrefix + `[_-]?tokens|[A-Za-z0-9]*(?:[-_][A-Za-z0-9]*)*token)`

// bareValue 裸值形态：可选的 scheme 前缀（RFC 7235 方案词 + 空白）连同凭据体
// 一起算作值——方案词锚定规则先行打码后留下 `key=Bearer ****`，kv 规则若只吃
// `Bearer` 一词会留下孤儿掩码段；整体吞掉后输出收敛为单段 `key=****`。
// 方案词表与 auth-scheme-token 规则同源，两处一起改（guardx#81）。
const bareValue = `((?:(?:Bearer|Basic|Negotiate|Digest)\s+)?[^\s&'"]+)`

// kvSeparator 键与值之间的分隔段（含键自身的闭引号）：捕获保留，替换时原样
// 回填——「"key": "v"」打码后仍是「"key": "****"」，JSON 行的结构不再被
// 打码动作本身破坏（oagentkit/guardx#44：此前 Repl 把分隔段吞成 `=`，冒号
// 变等号、引号丢失，日志采集侧的 JSON 解析器整行降级）。
const kvSeparator = `(["']?\s*[=:]\s*)`

var builtinRules = []Rule{
	{
		// URL 内嵌凭据：锚点是 `://user:pass@` 的 userinfo **文法**，不是 scheme
		// 名——scheme 按 RFC 3986 通用形状匹配（guardx#64/#75）：驱动后缀
		// （postgresql+psycopg2://）、加密后缀（rediss://、mqtts://）、私有
		// scheme（sftp://）形形色色，枚举词表永远追不上，词表再全也救不了
		// 文法缺陷（guardx#77 的教训）。用户名段可空（guardx#77）：RFC 3986
		// 允许省略 user 只写密码——`redis://:pass@host` 是 Redis 官方文档
		// 形态，量词 + 会整条失配、密码原文落日志。
		// 刻意**不**掩「纯用户名无密码」形态（ssh://git@github.com）：用户名
		// 不是凭据，该形态是 git clone 日志最高频 URL，整体掩码会毁掉日志
		// 定位；token-作-用户名（ghp_xxx@host）由 vendor-token-prefix 兜住。
		Name: "url-embedded-credential",
		Re:   regexp.MustCompile(`(?i)\b([A-Za-z][A-Za-z0-9+.-]*)://([^\s:@/]*):([^\s@/]+)@`),
		Repl: "$1://$2:****@",
	},
	{
		// 方案词/jwt/vendor 三组锚定**凭据体自身**（RFC 7235 方案词后的凭据
		// 串、eyJ 三段式、平台特征前缀）——按「精确在前、宽泛在后」的总原则
		// 排在键值对之前：kv 规则吃掉 `auth=Bearer` 的键值形态后，锚点就没了
		// （实测回归：auth 入词表后 `auth=Bearer <JWT>` 的 JWT 反而漏网）。
		// 方案词表（guardx#81）：此前只有 Bearer——Basic <base64> 在非词表
		// 键名（auth_header/proxy_auth）下整段漏网，base64 一解码即明文
		// user:pass。刻意不含 Token：散文里 "tokens 500" 是 LLM usage 计量行
		// （guardx#52 契约：计量字段不误掩），RE2 无环视分不开这两种词形。
		Name: "auth-scheme-token",
		Re:   regexp.MustCompile(`(?i)\b(Bearer|Basic|Negotiate|Digest)\s+[A-Za-z0-9._~+/=-]+`),
		Repl: "$1 ****",
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
		// glpat-（GitLab PAT，guardx#57：v0.19.0 实测泄漏）；AIza（Google API
		// key，官方格式 AIza+35 位，guardx#75 收编，{30,} 容截断残段）。
		Name: "vendor-token-prefix",
		Re:   regexp.MustCompile(`\b(sk-ant-[A-Za-z0-9_-]{16,}|sk-(?:proj|svcacct|None)-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|AIza[A-Za-z0-9_-]{30,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b`),
		Repl: "****",
	},
	{
		// 长十六进制（guardx#75 收编，agent-memory 生产实证）：裸 hex ≥32 是
		// API secret/私钥材料的高频形状（32 位 hex API key 整值泄漏）。与
		// vendor 前缀是不同锚定类（形状 vs 厂商前缀），单列一条。已知代价：
		// SHA 校验和（40/64）与无横线 UUID（32）一并被掩——over-mask 是
		// 安全方向的错，与凭证词表吞 bypass 同款取舍。
		Name: "long-hex-secret",
		Re:   regexp.MustCompile(`(?i)\b[0-9a-f]{32,}\b`),
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
		// 双引号值形态含转义引号（\"）——值字符集补「反斜杠转义的任意字符」，
		// 否则 "a\"b" 只掩到内嵌引号、留下 b"} 半截残形（oagentkit/guardx#50）。
		Re:   regexp.MustCompile(`(?i)\b(key)` + kvSeparator + `("(?:\\.|[^"\\\n])*")`),
		Repl: `$1$2"****"`,
	},
	{
		Name: "key-value-single-quoted",
		Re:   regexp.MustCompile(`(?i)\b(key)` + kvSeparator + `('[^'\n]*')`),
		Repl: `$1$2'****'`,
	},
	{
		// 截断值兜底（oagentkit/guardx#50）：日志超长截断落在值的开引号之后
		//（无收尾引号）时，闭引号规则全部失配 ⇒ 整值原文泄漏。掩码保留开
		// 引号（`"****`）——掩值不改引号的有无，下游「值以引号收尾」的模式
		// 仍可匹配。闭引号形态存在时本规则不命中（[^"\n]* 跨不过闭引号）。
		// ⚠️ 锚点必须 (?m)$（guardx#121）：截断不只发生在整段载荷末尾——
		// shipper 按行截断（Loki/Fluentd 行上限、head -c、终端裁剪）后后面
		// 还有行是常态，裸 $ 只认整段末尾，逐行截断形态整值原文泄漏。(?m) 下
		// $ 认行尾；[^"\n]* 本就不跨行，值匹配仍被锁在单行内，语义自洽。
		// 幂等不受影响：已掩行尾 `"****` 二次命中替换为自身。
		Name: "key-value-double-quoted-truncated",
		Re:   regexp.MustCompile(`(?im)\b(key)` + kvSeparator + `("[^"\n]*$)`),
		Repl: `$1$2"****`,
	},
	{
		Name: "key-value-single-quoted-truncated",
		Re:   regexp.MustCompile(`(?im)\b(key)` + kvSeparator + `('[^'\n]*$)`),
		Repl: `$1$2'****`,
	},
	{
		// 整值掩（oagentkit/guardx#51）：凭证值本身是 JSON 数组/对象时，裸值
		// 规则只吃到首个空白/引号（`****"a","b"]` 半截对象）；单层括号平衡
		// 形态（含截断兜底）整值换掉——按字段名整值替换语义。截断兜底的
		// 锚点用 (?m)$（guardx#121，理由同 key-value-*-truncated：逐行截断
		// 后面还有行是常态，裸 $ 只认整段末尾）。
		Name: "key-value-bracket",
		Re:   regexp.MustCompile(`(?im)\b(key)` + kvSeparator + `(\[[^\]\n]*\]|\{[^\}\n]*\}|\[[^\]\n]*$|\{[^\}\n]*$)`),
		Repl: `$1$2****`,
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
		Re:   regexp.MustCompile(`(?i)` + credentialKeyPart + kvSeparator + `("(?:\\.|[^"\\\n])*")`),
		Repl: `$1$2"****"`,
	},
	{
		Name: "credential-kv-single-quoted",
		Re:   regexp.MustCompile(`(?i)` + credentialKeyPart + kvSeparator + `('[^'\n]*')`),
		Repl: `$1$2'****'`,
	},
	{
		// 截断/括号整值兜底：语义同 key-value 组的同名规则（#50/#51），键面
		// 换凭证词表。截断兜底锚点 (?m)$（guardx#121，理由同上）。
		Name: "credential-kv-double-quoted-truncated",
		Re:   regexp.MustCompile(`(?im)` + credentialKeyPart + kvSeparator + `("[^"\n]*$)`),
		Repl: `$1$2"****`,
	},
	{
		Name: "credential-kv-single-quoted-truncated",
		Re:   regexp.MustCompile(`(?im)` + credentialKeyPart + kvSeparator + `('[^'\n]*$)`),
		Repl: `$1$2'****`,
	},
	{
		Name: "credential-kv-bracket",
		Re:   regexp.MustCompile(`(?im)` + credentialKeyPart + kvSeparator + `(\[[^\]\n]*\]|\{[^\}\n]*\}|\[[^\]\n]*$|\{[^\}\n]*$)`),
		Repl: `$1$2****`,
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
// **并集顺序契约**（guardx#75：两个消费仓各自用注释钉死的顺序纪律，在此升格
// 为可依赖的契约，不是实现细节）：
//
//   - 顺序固定为「先内置、后扩展」，每组内部按声明顺序。需要「扩展先行」的
//     调用方（形态比内置更精确、要抢在粗规则前保线索）用函数组合实现：
//     先跑自己的规则，再过 RedactWith(s, nil)——此时扩展先见原文，与内置的
//     幂等性由调用方自行保证。
//   - 扩展规则看到的是内置规则处理**之后**的文本：内置打码保结构（scheme、
//     用户名、键名留着），扩展规则仍能锚定这些结构；但别指望拿到原始凭据——
//     内置已命中的部分早成 ****。
//   - 二次打码幂等：内置掩码是固定字面 ****，对已掩文本重复 Redact 不再改动；
//     扩展规则也应满足同款幂等（对 **** 无操作的规则天然满足）。
//   - 定位线索保留：MaskStyleHint 档的线索只作用于捕获组（Group>0），组捕获
//     失败回退全量打码——既不丢「认得出哪条凭据」的能力，也不留凭据尾巴。
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
// 并集顺序与 RedactWith 同一契约（guardx#75）：先内置、后扩展，快照里的顺序
// 就是应用顺序；扩展规则见已掩文本、依赖内置保留的结构锚点，详见 RedactWith。
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
//
// 组捕获失败（Group 越界、可选组未参与匹配、对子串二次匹配失败）一律回退
// **全量打码**而非整段 hint（guardx#69）：调用方指定 Group 就是在声明「匹配
// 里有上下文」，整段 hint 保留的尾 4 字符正是 Rule.Group 注释自述的
// 「线索=泄露」陷阱——宁可丢线索，不留尾巴。
func hintMatch(r Rule, m string) string {
	if r.Group <= 0 {
		return MaskHintWith(m, r.Keep)
	}
	idx := r.Re.FindStringSubmatchIndex(m)
	if idx == nil || r.Group >= len(idx)/2 {
		return fullMask
	}
	lo, hi := idx[2*r.Group], idx[2*r.Group+1]
	if lo < 0 || hi < 0 {
		// 该组没参与匹配（可选组未命中）→ 全量打码兜底
		return fullMask
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
//
// ⚠️ guardx#63/#76 起类型化容器同一下探：map[string]string、[]string、
// []map[string]any、struct 导出字段（字段名过键名判定）经反射递归——此前
// 类型开关只认 any 解码形态，类型化容器静默漏脱（脱敏器最危险的失效形态）。
// 边界：未导出字段反射不可读（原样，请传导出形态）；json.Number 特赦
// （数字字面量保形）；[]byte 是二进制不是文本（原样）。输出为副本，入参不动。
func RedactValue(v any) any {
	return redactWalk(v, nil, ValueOptions{})
}

// RedactValueOpts 同 RedactValue，接受 ValueOptions（自定义键名判定等）。
func RedactValueOpts(v any, opts ValueOptions) any {
	return redactWalk(v, nil, opts)
}
