// 结构化 JSON 脱敏（oagentkit/guardx#44）：文本规则对 JSON 行做字符级替换，
// 打码动作本身可能破坏 JSON 结构（引号/冒号形态错位）；本文件提供键感知的
// 结构化路径——先解 JSON、按键名打码、重新序列化，输出恒为合法 JSON。

package logredact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
)

// jsonCredentialKeyRe 结构化路径的键名命中判定：键以凭证词**结尾**即命中
// （snake/kebab 复合键、camelCase 拼接、复数形态均可——"db_password"、
// "github_token"、"apiKey"、"passwords"）。
//
// 与文本规则的 credentialSuffix 同一口径但独立实现：文本键「复合前缀+末词」
// 的判定长在 kv 正则里，无法复用成独立的键名判定；两处词表要一起改。
// 刻意不含裸 "key"（"sort_key"/"cache_key" 这类中性键误伤面太大——文本规则
// 的 key-value 组兜的是 `key=` 紧邻形态，结构化键名没有这层形态约束）。
var jsonCredentialKeyRe = regexp.MustCompile(
	`(?i)(?:tokens?|secrets?|pass(?:words?|wds?|es)?|pwds?|passphrases?|api[_-]?keys?|access[_-]?keys?|private[_-]?keys?|secret[_-]?keys?|client[_-]?keys?|auths?|authorization|credentials?|kubeconfig)$`)

// maskLiteral 凭证词键的整值打码体。
const maskLiteral = "****"

// RedactJSON 对 JSON 载荷做结构化脱敏，输出恒为合法 JSON：
//
//   - 合法 JSON：解码（json.Number 保数字字面量）→ 键感知递归打码
//     （凭证词键的**整值**打码为 "****"，字符串值过文本规则兜内嵌连接串/
//     JWT/Bearer）→ 重新序列化。键的声明序经 map 归一后按字母序输出——
//     打码保的是**结构合法**，不是字节保形。
//   - 非法 JSON：回落文本规则（与 Redact 同口径）——不是错误，调用方无须
//     区分两条路径的返回值。
//
// 场景：结构化日志行/事件载荷在采集侧要过 JSON 解析器（Loki/ELK/事件面），
// 文本规则打码后的 `"api_key=****}` 会让整行降级为 raw 文本、字段索引全丢
// ——排查方向被带偏到采集管道（oagentkit/guardx#44）。
func RedactJSON(data []byte) []byte {
	if json.Valid(data) {
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err == nil {
			if out, err := json.Marshal(redactWalk(v, nil)); err == nil {
				return out
			}
		}
	}
	return []byte(Redact(string(data)))
}

// redactWalk 键感知递归打码：凭证词键的整值打码（无论原值是字符串、数字、
// 对象还是数组——键表内的键，值必被打码，不留「对象形态绕过」的缝）；其余
// 字符串值过文本规则；容器下探；标量原样。payload 非 nil 时载荷字段先于
// 凭证词判定（载荷裁剪语义见 payload.go）。
func redactWalk(v any, payload map[string]struct{}) any {
	switch t := v.(type) {
	case string:
		return Redact(t)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, vv := range t {
			if _, isPayload := payload[k]; isPayload {
				if s, isStr := vv.(string); isStr {
					if payloadMarkerRe.MatchString(s) {
						out[k] = s // 已是标记 ⇒ 原样保留（幂等）
						continue
					}
					out[k] = fmt.Sprintf(payloadMarkerFormat, len(s))
					continue
				}
			}
			if jsonCredentialKeyRe.MatchString(k) {
				out[k] = maskLiteral
				continue
			}
			out[k] = redactWalk(vv, payload)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, vv := range t {
			out[i] = redactWalk(vv, payload)
		}
		return out
	default:
		return v
	}
}
