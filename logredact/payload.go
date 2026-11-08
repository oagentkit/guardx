package logredact

import (
	"encoding/json"
	"fmt"
	"regexp"
)

// payloadMarkerFormat 载荷字段被裁剪后的标记格式（%d = 原值的**字节长度**）。
//
// 为什么是「只记长度」而不是「打码」：载荷不是凭据形状——一段 base64 私钥、
// 一份文件内容、一个任意 API body，长得就是字母数字，形状规则认不出来。
// 要防的是**完整落盘**，而审计要的只是「这里有 135 字节的东西」。
//
// 为什么长度取**原值**的长度：裁剪若排在形状规则之后，量到的就是残片的长度
// （135 字节的私钥先被打码，再量长度就报成 21）——那是谎报。本包的入口
// 把「先裁剪、后脱敏」的顺序**焊在函数内部**，调用点没有犯错的余地。
const payloadMarkerFormat = "<%d bytes scrubbed>"

// payloadMarkerTruncatedFormat 载荷字段以**截断形态**被裁剪时的标记格式。
//
// 什么时候会走到这一形态：日志落盘前的截断（按字节上限裁、按行切分多行
// JSON、框架的 maxMessageLen）几乎必然把字符串字面量切在半途——值只有开头
// 引号、没有闭合引号。此时裁的不是「完整载荷」，而是「载荷的残片」：
// 原文在上游存在过、且**已被截断**这件事本身就是必须可审计的信号（越长的
// 载荷越容易被截断，缺口方向正好落在最需要保护的一侧——guardx#120）。
//
// 与闭合形态的标记刻意**不同字**：告警侧靠这个后缀把「载荷被完整裁剪」与
// 「载荷被截断后裁剪」区分开（后者往往意味着日志管道在上游丢过内容），
// 用 HasTruncatedPayloadMarker 判定，别手写字符串匹配把信号写散。
const payloadMarkerTruncatedFormat = "<%d bytes scrubbed, truncated>"

// payloadMarkerRe 识别「已经是标记」的值（闭合形态与截断形态都算）。
//
// 幂等用：载荷可能被同一条脱敏链路处理不止一次（多道出口、日志重放）。
// 若第二遍把标记本身又量了一遍，就会报出 "<21 bytes scrubbed>"——
// 一个凭空捏造的长度，比不幂等更坏。
var payloadMarkerRe = regexp.MustCompile(`^<\d+ bytes scrubbed(?:, truncated)?>$`)

// RedactPayloads 把 fields 指定的载荷字段裁剪成「只记长度」的标记，再做形状脱敏。
//
// **顺序由本函数保证**：载荷裁剪先于形状规则（见 payloadMarkerFormat 的说明）。
// 这正是 issue 里说的「「先裁剪再脱敏」应当由函数内部保证，而不是由调用点的
// 书写顺序保证」——顺序写反不报错，只是报出来的大小是错的。
//
// fields 是**字段名白名单**（如 "content" / "content_base64" / "body"）：
// 只裁剪这些字段的值，其余原样。刻意不给默认表——「哪些字段算载荷」是
// 调用方的口径，库里替它猜就等于替它决定什么会落盘。
//
// 裁剪只作用于**字符串形态**的字段值（载荷就是字符串：一段 base64、一份内容）。
// 对象/数组形态的值本函数不动它（那是结构化入口 RedactPayloadValue 的射程）。
//
// 截断兜底（guardx#120）：文本被日志管道截断、字段值的字符串字面量没有
// 闭合引号时，冒号后的剩余整段替换成**截断形态**标记（"<N bytes scrubbed,
// truncated>"）——残片原文不落盘，截断本身是告警信号（HasTruncatedPayloadMarker）。
//
// 高频路径（日志热路径、每条 tool_call 都过一遍）用 NewPayloadRedactor，
// 别每次重建正则。
func RedactPayloads(s string, fields ...string) string {
	return RedactPayloadsWith(s, fields, nil)
}

// RedactPayloadsWith = RedactPayloads + 扩展规则。
//
// 扩展规则仍然排在**最后**（与 RedactWith 的口径一致：先内建、后扩展）；
// 载荷裁剪仍在最前。三段的顺序是：载荷裁剪 → 内建规则 → 扩展规则。
func RedactPayloadsWith(s string, fields []string, extra []Rule) string {
	s = scrubPayloadText(s, fields)
	return RedactWith(s, extra)
}

// RedactPayloadValue 结构化形态：递归把 fields 指定的字段裁剪成「只记长度」的标记，
// 其余字符串按 RedactValue 的口径做形状脱敏（含凭证词键的整值打码——键感知
// 走 redactWalk 同一份判定）。
//
// 与 RedactPayloads 语义一致（同一份判定表），差别只在形态：它吃已解码的值、
// 吐已解码的值，可用于「按字段名裁剪后再落库」的结构化载荷管道。
//
// 裁剪只作用于**字符串形态**的字段值；非字符串形态（对象/数组/数字）的值
// 原样保留，只递归下探——被裁掉的是「载荷」，不是「字段所在的那个对象」。
func RedactPayloadValue(v any, fields ...string) any {
	set := make(map[string]struct{}, len(fields))
	for _, f := range fields {
		if f != "" {
			set[f] = struct{}{}
		}
	}
	return redactWalk(v, set, ValueOptions{})
}

// NewPayloadRedactor 返回可复用的「载荷裁剪 + 形状脱敏」函数（字段集与规则表
// 在构造时**快照**一次）。
//
// 与 NewRedactor 同构：高频路径（日志热路径、每条 tool_call 都过一遍）用它，
// 别每次调用现编正则。返回的函数是并发安全的（只读快照，不改共享状态）。
func NewPayloadRedactor(fields []string, extra []Rule) func(string) string {
	snapshot := make([]Rule, 0, len(builtinRules)+len(extra))
	snapshot = append(snapshot, builtinRules...)
	snapshot = append(snapshot, extra...)

	// 正则在构造时编一次：字段集是调用方给的，编译失败只可能是字段名里有
	// 非法正则元字符——但字段名不是正则，所以 QuoteMeta 之后必然能编过。
	res := make([]*regexp.Regexp, 0, len(fields))
	for _, f := range fields {
		if f == "" {
			continue
		}
		res = append(res, payloadFieldRe(f))
	}

	return func(s string) string {
		s = scrubPayloadTextWith(s, res)
		for _, r := range snapshot {
			s = applyRule(s, r)
		}
		return s
	}
}

// scrubPayloadText 按字段名裁剪文本里的载荷字段（JSON 字符串值形态）。
func scrubPayloadText(s string, fields []string) string {
	res := make([]*regexp.Regexp, 0, len(fields))
	for _, f := range fields {
		if f == "" {
			continue
		}
		res = append(res, payloadFieldRe(f))
	}
	return scrubPayloadTextWith(s, res)
}

// scrubPayloadTextWith 用已编译好的字段正则裁剪载荷。
//
// 两种形态（guardx#120）：
//   - **闭合**——值是完整的 JSON 字符串字面量，替换成「只记解码后长度」的
//     标记，留下的仍是合法 JSON 字符串；
//   - **截断**——日志管道把字面量切在半途（无闭合引号），把冒号后的剩余
//     整段替换成「截断形态」标记。长度取剩余字节数即可：精度不重要，
//     **不落原文**才是契约；截断本身是告警信号（见 payloadMarkerTruncatedFormat）。
func scrubPayloadTextWith(s string, res []*regexp.Regexp) string {
	for _, re := range res {
		s = re.ReplaceAllStringFunc(s, func(m string) string {
			g := re.FindStringSubmatch(m)
			if len(g) < 5 {
				return m
			}
			// 闭合形态：g[1] = 键与冒号（含原有空白），g[2] = 带引号的原值。
			if g[2] != "" {
				n, marker := jsonStringLen(g[2])
				if marker {
					return m // 已经是标记了 ⇒ 原样保留（幂等）
				}
				return g[1] + `"` + fmt.Sprintf(payloadMarkerFormat, n) + `"`
			}
			// 截断形态：g[3] = 键与冒号，g[4] = 开头引号 + 被切在半途的残片。
			// json 解不出来（没有闭合引号），长度取字面字节数——宁可偏大，
			// 也不把「有东西」报成「没有」。截断形态必然不是标记本身
			// （标记总是写成闭合形态），无需再做幂等判断。
			return g[3] + `"` + fmt.Sprintf(payloadMarkerTruncatedFormat, len(g[4])) + `"`
		})
	}
	return s
}

// payloadTruncatedMarkerRe 在整段文本里定位截断形态标记（非锚定——
// 标记是日志行的一部分，不是整行）。
var payloadTruncatedMarkerRe = regexp.MustCompile(`<\d+ bytes scrubbed, truncated>`)

// HasTruncatedPayloadMarker 报告 s 是否含「截断形态载荷」的裁剪标记——
// 即日志管道在脱敏**之前**就把载荷字段切断了。
//
// 这是 guardx#120 修法里的告警信号出口：截断形态的标记与闭合形态**不同字**
// （"<N bytes scrubbed, truncated>"），本函数把它收成单一判定点，告警侧
// （审计扫描、落盘前检查）用它，别各处手写字符串匹配把信号写散。
//
// 注意语义边界：本函数判定的是「文本里有没有截断标记」，前提是文本已经
// 过本包的载荷裁剪；对未脱敏的原文它恒返回 false——先裁剪、后探测。
func HasTruncatedPayloadMarker(s string) bool {
	return payloadTruncatedMarkerRe.MatchString(s)
}

// payloadFieldRe 匹配「"字段名": "字符串值"」形态——闭合与截断两种形态
// 各一个分支（guardx#120）：
//
//	("字段名"\s*:\s*)("(?:[^"\\]|\\.)*")        闭合：完整 JSON 字符串字面量
//	("字段名"\s*:\s*)("(?:[^"\\]|\\.)*\\?$)    截断：开头引号 + 到文本末尾都没有闭合引号
//
// 截断分支是日志落盘前截断（按字节上限裁、按行切分多行 JSON、框架的
// maxMessageLen）的兜底：没有它，被切在半途的字面量零命中——既不打码也
// 不告警，残片原文全量落盘。末尾的 `\\?` 兜住「恰好切在反斜杠后」的形态
// （孤立反斜杠构不成转义对，但同样是原文残片）。键名按**字面量**匹配
// （QuoteMeta）——字段名不是正则，调用方给的什么就是什么。
//
// 分支顺序：闭合在前。闭合值能被第一分支完整吃掉（贪婪但止于闭合引号）；
// 只有到文本末尾都没有闭合引号的残片才轮得到第二分支。两个分支的捕获组
// 各自独立（g[1]/g[2] 闭合，g[3]/g[4] 截断），scrubPayloadTextWith 据此分派。
//
// 只匹配字符串值：载荷是字符串形态；对象/数组形态的载荷由结构化入口处理。
func payloadFieldRe(field string) *regexp.Regexp {
	k := regexp.QuoteMeta(field)
	return regexp.MustCompile(`("` + k + `"\s*:\s*)("(?:[^"\\]|\\.)*")|("` + k + `"\s*:\s*)("(?:[^"\\]|\\.)*\\?$)`)
}

// jsonStringLen 取 JSON 字符串字面量的**解码后**字节长度。
//
// 第二个返回值报「这个值本身是不是一个载荷标记」——已是标记的原样保留（幂等）。
//
// 解不出来时退回字面长度：宁可报一个偏大的数，也不要报 0——0 会被读成
// 「这里什么都没有」，而实际上有东西。
func jsonStringLen(lit string) (int, bool) {
	var v string
	if err := json.Unmarshal([]byte(lit), &v); err != nil {
		return len(lit), false
	}
	return len(v), payloadMarkerRe.MatchString(v)
}
