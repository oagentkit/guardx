// 结构化 JSON 脱敏（oagentkit/guardx#44）：文本规则对 JSON 行做字符级替换，
// 打码动作本身可能破坏 JSON 结构（引号/冒号形态错位）；本文件提供键感知的
// 结构化路径——先解 JSON、按键名打码、重新序列化，输出恒为合法 JSON。

package logredact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"unicode/utf8"
)

// jsonCredentialKeyRe 结构化路径的键名命中判定：键含凭证词（作为 [-_]
// 分隔的**完整段**、后面允许接任意后续段）即命中（snake/kebab 复合键、
// camelCase 拼接、复数形态均可——"db_password"、"github_token"、"apiKey"、
// "passwords"、"password_hash"、"api_key_prefix"）。
//
// 锚定口径（oagentkit/guardx#132）：凭证词不要求是键的最后一个段——
// password_hash（bcrypt 摘要，Laravel/Django/DRF 生态标配字段）、
// api_key_prefix、password_salt 这类「凭证词在中间」的键同样命中。此前
// 只锚 `$` 末段，这类键结构化面不整值打码、值过形状规则后原文保留。
// 后续段要求 [_-] 分隔边界：凭证词后直连字母的普通词（"author"）不误伤。
//
// token 复数收窄（oagentkit/guardx#52，与文本面 credTokenPrefix 同口径）：
// `tokens` 结尾的键只在「凭证前缀段 + tokens」或整键恰为 "tokens" 时命中——
// OpenAI 兼容 usage 块的 prompt_tokens / completion_tokens / total_tokens /
// cached_tokens / reasoning_tokens 等计量字段不再整值打码（此前 v0.18.0 把
// 它们全打成 "****"，计价/评测/配额读到掩码）。单数 `token` 结尾保持全量
// 命中（*_token / xToken 几乎恒为凭证）——token 词**不**参与 #132 的任意段
// 放开（token_expiry 这类计量键按 #52 契约保留，token 词仍只锚键尾）。
// 复数分支的键名前缀段 + 凭证前缀必须**同时**成立（分支内 CRED 必选），
// 防止 "scout_tokens" 借「s_cout_」分段绕进凭证前缀枚举。
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
	`(?i)(?:(?:` + jsonCredentialSuffixGeneral + `)(?:[_-][a-z0-9_-]*)*$` +
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
	// 键形态而维护的整套绕行脱敏器。）struct 路径传的是 jsonFieldName 取的
	// 键名——json tag 首段优先、无 tag/`-` 回落字段名（guardx#130），与
	// map 形态见到的键同一口径。
	IsCredentialKey func(key string) bool
	// ExtraRules 追加到字符串叶子文本规则的扩展表（guardx#76 的**值模式**
	// 检测缝）：结构化路径的每个字符串叶子按「先内置、后扩展」过
	// RedactWith——手机号/身份证这类**值本身即敏感、无键名可依**的形态由
	// 调用方注入正则规则，不必再自研结构递归器（agent-harness 整包 pii 的
	// 递归 ApplyValue 由此收编，只留值模式正则）。刻意不进内置表：值模式
	// 是地区/产品口径（大陆手机号正则会误掩 11 位订单号/毫秒时间戳），
	// 内置表守的是通用凭证语义。
	ExtraRules []Rule
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

// RedactJSONOpts 同 RedactJSON，接受 ValueOptions（自定义键名判定、值模式
// 扩展规则等；非法 JSON 回落文本规则时 ExtraRules 同样生效）。
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
	return []byte(RedactWith(string(data), opts.ExtraRules))
}

// redactWalk 键感知递归打码：凭证词键的整值打码（无论原值是字符串、数字、
// 对象还是数组——键表内的键，值必被打码，不留「对象形态绕过」的缝）；其余
// 字符串值过文本规则（含 opts.ExtraRules）；容器下探；标量原样。payload
// 非 nil 时载荷字段先于凭证词判定（载荷裁剪语义见 payload.go）。
// opts.IsCredentialKey 非 nil 时作为内置词表之上的追加键名判定。
// 类型开关外的类型化容器（guardx#63/#76）经 redactReflect 反射下探。
func redactWalk(v any, payload map[string]struct{}, opts ValueOptions) any {
	return redactWalkDepth(v, payload, opts, 0)
}

// maxWalkDepth 结构递归深度上限：防类型化 Go 值的自引用环（JSON 解码值不可
// 能成环，类型化容器可以——无上限会栈溢出挂死脱敏链路）。超限的容器原样
// 返回；字符串叶子不递归、不受上限影响。64 层已远超真实载荷嵌套深度。
const maxWalkDepth = 64

var (
	stringType       = reflect.TypeFor[string]()
	jsonNumberType   = reflect.TypeFor[json.Number]()
	mapStringAnyType = reflect.TypeFor[map[string]any]()
	sliceAnyType     = reflect.TypeFor[[]any]()
)

// isCredentialKeyName 键名判定：内置词表 + 调用方回调叠加（回调只加不减，
// guardx#51 契约：返回 false 不豁免内置命中）。
func isCredentialKeyName(key string, opts ValueOptions) bool {
	return jsonCredentialKeyRe.MatchString(key) ||
		(opts.IsCredentialKey != nil && opts.IsCredentialKey(key))
}

func redactWalkDepth(v any, payload map[string]struct{}, opts ValueOptions, depth int) any {
	switch t := v.(type) {
	case string:
		return RedactWith(t, opts.ExtraRules)
	case map[string]any:
		if depth >= maxWalkDepth {
			return v
		}
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
			if isCredentialKeyName(k, opts) {
				out[k] = maskLiteral
				continue
			}
			out[k] = redactWalkDepth(vv, payload, opts, depth+1)
		}
		return out
	case []any:
		if depth >= maxWalkDepth {
			return v
		}
		out := make([]any, len(t))
		for i, vv := range t {
			out[i] = redactWalkDepth(vv, payload, opts, depth+1)
		}
		return out
	default:
		return redactReflect(v, payload, opts, depth)
	}
}

// redactReflect 类型化容器的反射下探（guardx#63/#76）：redactWalk 的类型
// 开关只认 any 解码形态（map[string]any/[]any），map[string]string、
// []string、[]map[string]any、struct 导出字段等 Go 侧类型化容器此前一律
// default 原样返回——脱敏器最危险的失效形态：**静默漏脱**（事件载荷以类型化
// 容器传入时连接串/Bearer 头原文落库）。本函数按 map/slice/array/struct/
// 指针/接口递归，语义与 any 形态同源：字符串键/结构体键名（json tag 首段
// 优先、回落字段名，guardx#130）过键名与载荷判定、字符串叶子过文本规则
// （含 ExtraRules）、容器逐元素下探。
//
// 刻意的边界：
//   - json.Number 特赦——它是命名 string，但是数字字面量不是文本（JSON 路径
//     大整数保形依赖它原样透传）；其余命名 string 类型（type Password string）
//     仍是文本。
//   - []byte（guardx#obs88 交叉面收口）：UTF-8 文本载荷不再豁免——JSON 走
//     RedactJSON 键感知打码、非 JSON 文本走文本规则（与顶层 RawMessage 同一
//     语义）；非 UTF-8 才视为二进制原样（检测面为空，base64 落盘）。此前嵌套
//     容器里的 []byte 一律原样——同一份凭证包一层 map 即绕开打码（obs#88）。
//   - error 叶子（obs#77 语义推广到嵌套）：标准 error 的文本在 unexported
//     字段、反射下探够不到——类型断言直取 Error() 过文本规则。此前嵌套层
//     error 原样落盘。
//   - 未导出字段反射不可读（walkReflectStruct 原样保留）。
//   - 输出为副本（新容器/新结构体），不污染入参。
func redactReflect(v any, payload map[string]struct{}, opts ValueOptions, depth int) any {
	rv := reflect.ValueOf(v)
	if !rv.IsValid() {
		return v
	}
	// error 叶子先于一切容器/反射处理（obs#88：嵌套层与顶层同语义——顶层在
	// 消费方类型开关里做，嵌套层在这里做，单源 Redact 文本规则）。
	if err, ok := v.(error); ok {
		return Redact(err.Error())
	}
	// any 形态快路径：交回类型开关，键判定/载荷/下探同一份实现（嵌在类型化
	// 容器里的 any 容器与顶层 any 容器行为一致）
	switch rv.Type() {
	case mapStringAnyType, sliceAnyType:
		return redactWalkDepth(rv.Interface(), payload, opts, depth+1)
	}
	switch rv.Kind() {
	case reflect.String:
		if rv.Type() == jsonNumberType {
			return v
		}
		return RedactWith(rv.String(), opts.ExtraRules)
	case reflect.Map:
		if rv.IsNil() {
			return v
		}
		return walkReflectMap(rv, payload, opts, depth)
	case reflect.Slice, reflect.Array:
		if rv.Kind() == reflect.Slice && rv.IsNil() {
			return v
		}
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			// UTF-8 文本载荷按文本处理（JSON→键感知 / 非 JSON→文本规则）；
			// 非 UTF-8 是真二进制——检测面为空，原样（base64 落盘）。
			b, _ := v.([]byte)
			if !utf8.Valid(b) {
				return v
			}
			if json.Valid(b) {
				return RedactJSON(b)
			}
			return RedactWith(string(b), opts.ExtraRules)
		}
		return walkReflectSeq(rv, payload, opts, depth)
	case reflect.Struct:
		return walkReflectStruct(rv, payload, opts, depth)
	case reflect.Pointer:
		if rv.IsNil() {
			return v
		}
		walked := redactReflect(rv.Elem().Interface(), payload, opts, depth+1)
		p := reflect.New(rv.Type().Elem())
		if wv := reflect.ValueOf(walked); wv.IsValid() && wv.Type().AssignableTo(p.Elem().Type()) {
			p.Elem().Set(wv)
			return p.Interface()
		}
		return v
	case reflect.Interface:
		if rv.IsNil() {
			return v
		}
		return redactReflect(rv.Elem().Interface(), payload, opts, depth+1)
	default:
		return v
	}
}

// stringValueOf 取「动态类型恰为 string」的值（命名 string 类型不算——掩码
// 字面量/裁剪标记塞回具体命名类型会类型错配）：载荷裁剪只作用于字符串形态。
func stringValueOf(val reflect.Value) (string, bool) {
	switch {
	case val.Type() == stringType:
		return val.String(), true
	case val.Kind() == reflect.Interface && !val.IsNil() && val.Elem().Type() == stringType:
		return val.Elem().String(), true
	}
	return "", false
}

// maskValueFor 目标元素/字段类型的整值打码值：string（含命名 string，经
// Convert 还型）与接口类型承载 "****"；复合类型（slice/array/map/pointer/
// struct）承载不了字符串字面量，但**凭证键命中后不放弃处理**（guardx#162）
// ——返回同类型空值清掉原文（slice 空切片、map 空 map、pointer nil、
// array/struct 零值），兑现「键表内的键，值必被打码」而不是转下探把形状
// 规则认不出的随机口令原样放行。数字/布尔返回 false 由调用方转下探：本体
// 不是凭据文本，any 形态里它们被掩是「能掩就掩」，类型化形态里掩不了是
// 类型系统的硬边界，不是承诺松动（#162 沿用本免责，不扩大改动面）。
func maskValueFor(t reflect.Type) (reflect.Value, bool) {
	switch t.Kind() {
	case reflect.String:
		if t == stringType {
			return reflect.ValueOf(maskLiteral), true
		}
		return reflect.ValueOf(maskLiteral).Convert(t), true
	case reflect.Interface:
		return reflect.ValueOf(maskLiteral), true
	case reflect.Slice:
		return reflect.MakeSlice(t, 0, 0), true
	case reflect.Map:
		return reflect.MakeMap(t), true
	case reflect.Pointer, reflect.Array, reflect.Struct:
		return reflect.Zero(t), true
	}
	return reflect.Value{}, false
}

// walkReflectMap 类型化 map 的下探：字符串键过载荷/键名判定（与 any 形态
// 同一份语义、同一份词表）；非字符串键（map[int]…）只下探值。
func walkReflectMap(rv reflect.Value, payload map[string]struct{}, opts ValueOptions, depth int) any {
	if depth >= maxWalkDepth {
		return rv.Interface()
	}
	et := rv.Type().Elem()
	out := reflect.MakeMapWithSize(rv.Type(), rv.Len())
	it := rv.MapRange()
	for it.Next() {
		k, val := it.Key(), it.Value()
		if k.Kind() == reflect.String {
			ks := k.String()
			if _, isPayload := payload[ks]; isPayload {
				if s, isStr := stringValueOf(val); isStr {
					if payloadMarkerRe.MatchString(s) {
						out.SetMapIndex(k, reflect.ValueOf(s)) // 已是标记 ⇒ 幂等保留
					} else {
						out.SetMapIndex(k, reflect.ValueOf(fmt.Sprintf(payloadMarkerFormat, len(s))))
					}
					continue
				}
				// 非字符串形态的载荷值：下探（与 any 形态同语义）
			}
			if isCredentialKeyName(ks, opts) {
				if mv, ok := maskValueFor(et); ok {
					out.SetMapIndex(k, mv)
					continue
				}
			}
		}
		out.SetMapIndex(k, walkAssignable(val, et, payload, opts, depth+1))
	}
	return out.Interface()
}

// walkReflectSeq 类型化 slice/array 的下探：元素逐个走（字符串元素过文本
// 规则，元素容器继续反射），类型与长度保形。
func walkReflectSeq(rv reflect.Value, payload map[string]struct{}, opts ValueOptions, depth int) any {
	if depth >= maxWalkDepth {
		return rv.Interface()
	}
	et := rv.Type().Elem()
	var out reflect.Value
	if rv.Kind() == reflect.Slice {
		out = reflect.MakeSlice(rv.Type(), rv.Len(), rv.Len())
	} else {
		out = reflect.New(rv.Type()).Elem()
		out.Set(rv)
	}
	for i := 0; i < rv.Len(); i++ {
		out.Index(i).Set(walkAssignable(rv.Index(i), et, payload, opts, depth+1))
	}
	return out.Interface()
}

// walkReflectStruct struct 的下探：**键名**过载荷/键名判定（Password/
// AuthToken 命中即整值掩码）；键名取 jsonFieldName（guardx#130：json tag
// 首段优先，序列化后 JSON 载荷里的真名——同一份数据走 map[string]any（键
// api_key）与走 struct（字段 APIKeyField、tag api_key）必须同一判定口径，
// 此前用 Go 字段名（不读 tag）判凭证词表，struct 形态静默漏脱）；tag 为
// `-`（明确不序列化）或缺失时回落字段名——回落保证值仍被下探，不因 tag
// 而整字段跳过。先整体拷贝再覆写下探结果——未导出字段（反射不可读）与
// 无需处理的原样保留。
func walkReflectStruct(rv reflect.Value, payload map[string]struct{}, opts ValueOptions, depth int) any {
	if depth >= maxWalkDepth {
		return rv.Interface()
	}
	t := rv.Type()
	out := reflect.New(t).Elem()
	out.Set(rv)
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		fv := rv.Field(i)
		name := jsonFieldName(f)
		if _, isPayload := payload[name]; isPayload {
			if s, isStr := stringValueOf(fv); isStr {
				if payloadMarkerRe.MatchString(s) {
					out.Field(i).Set(reflect.ValueOf(s)) // 已是标记 ⇒ 幂等保留
				} else {
					out.Field(i).Set(reflect.ValueOf(fmt.Sprintf(payloadMarkerFormat, len(s))))
				}
				continue
			}
			// 非字符串形态的载荷值：下探（与 any 形态同语义）
		}
		if isCredentialKeyName(name, opts) {
			if mv, ok := maskValueFor(f.Type); ok {
				out.Field(i).Set(mv)
				continue
			}
		}
		out.Field(i).Set(walkAssignable(fv, f.Type, payload, opts, depth+1))
	}
	return out.Interface()
}

// jsonFieldName struct 路径的键名（guardx#130）：json tag 首段优先——它是
// 序列化后 JSON 载荷里的真名（Go 惯例禁止字段名带下划线，凭证键只能活在
// tag 里）；tag 为 `-`（明确不序列化）或为空时回落 Go 字段名，与 permgate
// structFieldString 的 tag 读取同口径。载荷字段白名单与凭证词表、
// ValueOptions.IsCredentialKey 回调都用这个名字。
func jsonFieldName(f reflect.StructField) string {
	if tag, ok := f.Tag.Lookup("json"); ok {
		if n, _, _ := strings.Cut(tag, ","); n != "" && n != "-" {
			return n
		}
	}
	return f.Name
}

// walkAssignable 下探后回填到目标元素/字段类型：叶子文本规则返回裸 string，
// 命名 string 目标经 Convert 还型（type Password string 的字段掩码后仍是
// Password）；nil 接口叶子取目标零值；理论不可达的类型失配兜底取原值
// （宁可不改，不让脱敏链路 panic）。
func walkAssignable(val reflect.Value, dst reflect.Type, payload map[string]struct{}, opts ValueOptions, depth int) reflect.Value {
	var walked any
	switch {
	case val.Kind() == reflect.Interface && !val.IsNil():
		walked = redactReflect(val.Elem().Interface(), payload, opts, depth)
	case val.Kind() != reflect.Interface:
		walked = redactReflect(val.Interface(), payload, opts, depth)
	}
	if walked == nil { // nil 接口叶子（接口形态的空值）
		return reflect.Zero(dst)
	}
	wv := reflect.ValueOf(walked)
	if wv.Type() == stringType && dst.Kind() == reflect.String && dst != stringType {
		wv = wv.Convert(dst)
	}
	if wv.Type().AssignableTo(dst) {
		return wv
	}
	return val
}
