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
// token 复数收窄（oagentkit/guardx#52，与文本面 credTokenPrefix 同口径）：
// `tokens` 结尾的键只在「凭证前缀段 + tokens」或整键恰为 "tokens" 时命中——
// OpenAI 兼容 usage 块的 prompt_tokens / completion_tokens / total_tokens /
// cached_tokens / reasoning_tokens 等计量字段不再整值打码（此前 v0.18.0 把
// 它们全打成 "****"，计价/评测/配额读到掩码）。单数 `token` 结尾保持全量
// 命中（*_token / xToken 几乎恒为凭证）。复数分支的键名前缀段 + 凭证前缀
// 必须**同时**成立（分支内 CRED 必选），防止 "scout_tokens" 借「s_cout_」
// 分段绕进凭证前缀枚举。
//
// 与文本规则的词表同一口径但独立实现（文本键判定长在 kv 正则里，无法复用
// 成独立谓词；两处词表要一起改）。刻意不含裸 "key"（"sort_key"/"cache_key"
// 这类中性键误伤面太大）。
// jsonCredentialSuffixGeneral JSON 键面的非 token 凭证词表：与文本面
// credentialSuffixGeneral 同词同序，但分隔符收 [-_] 全集——文本 kv 的
// `api_?keys?` 只见下划线（键后紧邻 [=:'] 形态约束），JSON 键名没有这层
// 约束，kebab 拼法（x-api-key）必须命中（v0.18.1 修复：两处词表拆开声明，
// 不再共用常量——共用会把文本面的窄分隔符带进 JSON 面）。
const jsonCredentialSuffixGeneral = `(?:secrets?|pass(?:words?|wds?|es)?|pwds?|passphrases?|api[_-]?keys?|access[_-]?keys?|private[_-]?keys?|secret[_-]?keys?|client[_-]?keys?|auths?|authorization|credentials?|kubeconfig)`

var jsonCredentialKeyRe = regexp.MustCompile(
	`(?i)(?:(?:` + jsonCredentialSuffixGeneral + `)$` +
		`|token$` +
		`|^tokens$` +
		`|^(?:[a-z0-9]+(?:[_-][a-z0-9]+)*[_-])?` + credTokenPrefix + `[_-]?tokens$)`)

// IsCredentialKey 内置键名判定（结构化键名面）：键名是否命中内置凭证词表。
// 供集成方在自持管线里复用（jumpserver-kit 此前自写 isCredentialKey 兜
// authorization/bearer/cookie/key 形态，oagentkit/guardx#51——上游暴露谓词
// 后可只补自己的增量词表）。
func IsCredentialKey(key string) bool {
	return jsonCredentialKeyRe.MatchString(key)
}

// ValueOptions RedactValue / RedactJSON 结构化路径的行为选项（零值 = 内置
// 词表语义）。
type ValueOptions struct {
	// IsCredentialKey 追加的键名判定：返回 true 的键整值打码（**叠加**于
	// 内置词表之上；返回 false 不豁免内置命中——要豁免请走自持 Redactor，
	// 内置词表的「值必被打码」承诺不因回调而松动）。nil = 仅内置词表。
	// （oagentkit/guardx#51：集成方喂自己的 isCredentialKey，替掉为兜自家
	// 键形态而维护的整套绕行脱敏器。）
	IsCredentialKey func(key string) bool
}

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
	return RedactJSONOpts(data, ValueOptions{})
}

// RedactJSONOpts 同 RedactJSON，接受 ValueOptions（自定义键名判定等）。
func RedactJSONOpts(data []byte, opts ValueOptions) []byte {
	if json.Valid(data) {
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err == nil {
			if out, err := json.Marshal(redactWalk(v, nil, opts)); err == nil {
				return out
			}
		}
	}
	return []byte(Redact(string(data)))
}

// redactWalk 键感知递归打码：凭证词键的整值打码（无论原值是字符串、数字、
// 对象还是数组——键表内的键，值必被打码，不留「对象形态绕过」的缝）；其余
// 字符串值过文本规则；容器下探；标量原样。payload 非 nil 时载荷字段先于
// 凭证词判定（载荷裁剪语义见 payload.go）。opts.IsCredentialKey 非 nil 时
// 作为内置词表之上的追加键名判定。
func redactWalk(v any, payload map[string]struct{}, opts ValueOptions) any {
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
			if jsonCredentialKeyRe.MatchString(k) ||
				(opts.IsCredentialKey != nil && opts.IsCredentialKey(k)) {
				out[k] = maskLiteral
				continue
			}
			out[k] = redactWalk(vv, payload, opts)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, vv := range t {
			out[i] = redactWalk(vv, payload, opts)
		}
		return out
	default:
		return v
	}
}
