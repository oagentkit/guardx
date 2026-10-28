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

// payloadMarkerRe 识别「已经是标记」的值。
//
// 幂等用：载荷可能被同一条脱敏链路处理不止一次（多道出口、日志重放）。
// 若第二遍把标记本身又量了一遍，就会报出 "<21 bytes scrubbed>"——
// 一个凭空捏造的长度，比不幂等更坏。
var payloadMarkerRe = regexp.MustCompile(`^<\d+ bytes scrubbed>$`)

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
// 其余字符串按 RedactValue 的口径做形状脱敏。
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
	return redactValueWith(v, set)
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
func scrubPayloadTextWith(s string, res []*regexp.Regexp) string {
	for _, re := range res {
		s = re.ReplaceAllStringFunc(s, func(m string) string {
			g := re.FindStringSubmatch(m)
			if len(g) < 3 {
				return m
			}
			// g[1] = 键与冒号（含原有空白），g[2] = 带引号的原值。
			n, marker := jsonStringLen(g[2])
			if marker {
				return m // 已经是标记了 ⇒ 原样保留（幂等）
			}
			// 替换掉整个字符串字面量（含引号）——留下的仍是合法 JSON 字符串。
			return g[1] + `"` + fmt.Sprintf(payloadMarkerFormat, n) + `"`
		})
	}
	return s
}

// payloadFieldRe 匹配「"字段名": "字符串值"」形态。
//
// 值那一段按 JSON 字符串字面量匹配（处理转义），键名按**字面量**匹配
// （QuoteMeta）——字段名不是正则，调用方给的什么就是什么。
//
// 只匹配字符串值：载荷是字符串形态；对象/数组形态的载荷由结构化入口处理。
func payloadFieldRe(field string) *regexp.Regexp {
	return regexp.MustCompile(`("` + regexp.QuoteMeta(field) + `"\s*:\s*)("(?:[^"\\]|\\.)*")`)
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

// redactValueWith 递归裁剪载荷字段并做形状脱敏。
func redactValueWith(v any, payload map[string]struct{}) any {
	switch t := v.(type) {
	case string:
		return Redact(t)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, vv := range t {
			if _, ok := payload[k]; ok {
				if s, isStr := vv.(string); isStr {
					if payloadMarkerRe.MatchString(s) {
						out[k] = s // 已是标记 ⇒ 原样保留（幂等）
						continue
					}
					out[k] = fmt.Sprintf(payloadMarkerFormat, len(s))
					continue
				}
			}
			out[k] = redactValueWith(vv, payload)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, vv := range t {
			out[i] = redactValueWith(vv, payload)
		}
		return out
	default:
		return v
	}
}
