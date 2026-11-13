package logredact

import (
	"cmp"
	"net"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// Masker 低敏感掩码+令牌回填器（K8sGPT anonymize 形态，bianque spec
// 2026-09-14-aiops-uplift-design §3）：把目标机拓扑标识（IPv4/IPv6 + 调用方
// 注册的精确串）在进 LLM 前替换为 «Tn» 令牌，在最终展示面 Restore 回填原名
// ——LLM 解释里引用的「主机 «T1»」在报告中还原为真名，可读性与隐私兼得。
//
// 分级纪律：高敏感（密码/密钥/连接串/Bearer）不走本机制——那是 Redact 的领域，
// 删除后永不回填；Masker 只收低敏感拓扑标识，且回填只发生在展示面、不回灌二次
// LLM 输入（防掩码词表被 prompt 注入探测绕过）。令牌用全角书名号+序号，难以仿造；
// Restore 对未知令牌原样保留（不猜、不误回填）。
type Masker struct {
	mu      sync.Mutex
	next    int
	tokens  map[string]string // token → 原文
	origins map[string]string // 原文 → token（注册去重）
	// secrets 调用方经 AddSecret **显式**注册的原文（#122）：精确盲替换阶段
	// 只处理这批。动态注册（IP 模式命中时 maskLocked 记账）的原文**不**进
	// 精确阶段——它们下次出现仍由 IP 模式整段掩掉（同令牌），若进精确阶段
	// 的盲替换（strings.ReplaceAll 无边界判定），先见短 IP 后见以其为中部
	// 子串的长 IP 时会把长 IP 掩成「残段+旧令牌」，破坏「同址恒同令牌」
	// （guardx#100 自述不变量）与掩码形态（guardx#122）。
	secrets map[string]bool
}

// NewMasker 构造（零值不可用，一律经本构造）。
func NewMasker() *Masker {
	return &Masker{tokens: map[string]string{}, origins: map[string]string{}, secrets: map[string]bool{}}
}

// ipv4Re 低敏感默认模式：IPv4 地址（工具输出里最常见的拓扑标识）。
var ipv4Re = regexp.MustCompile(`\b(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b`)

// ipv6Re 低敏感默认模式的 IPv6 侧（guardx#100）：双栈/K8s 环境里 IPv6
// （fe80::1、2001:db8::5、::1、链路本地 zone 形）与 IPv4 同为常态拓扑标识，
// 默认模式只有 IPv4 时它们原文直通 LLM 输入——漏 mask 是本包纪律里的事故
// 方向，故 IPv6 与 IPv4 同等待遇（同 «Tn» 令牌空间、同址恒同令牌、Restore
// 回填）。
//
// 刻意不手写完整 IPv6 文法：**宽松捕获候选 + net.ParseIP 精确验证** 两段式。
// 理由有二。其一，RE2 无环视，完整文法离不开边界字符的消耗与回填；其二，
// 完整文法是多分支 alternation，Go regexp 取「最左优先」而非「最左最长」，
// 缩写形态会被更短的分支提前截断（如 2001:db8::5 被 `1::` 形态分支截成
// `2001:db8::`，剩下个裸 `5`）。候选词法只要求「至少两个冒号的
// 十六进制/点/冒号连续段（可带 [ ] 括号与 %zone 后缀）」——时间（12:30:45）、
// MAC（aa:bb:cc:dd:ee:ff）、作用域符（std::cafe）等同样满足候选词法，但
// ParseIP 判负后原样保留；宁可在候选层多验几段，不在结果层漏一段。
//
// 左边界放行冒号（guardx#133）：日志里「标签：地址」的高频写法
// （host:fe80::1、node:2001:db8::5）此前因边界排除冒号而整类漏掩。放开后
// 冒号身兼两职（标签边界 / ::1 的候选首字符），歧义由 maskStringLocked 的
// 剥首冒号重验化解——真负例（时刻/MAC/作用域符）由 ParseIP 判负路径保住，
// 边界不承担防误掩职责（它也防不了：候选验证才是精确闸门）。
var ipv6Re = regexp.MustCompile(
	`(?:^|[^0-9A-Za-z_])` + // 左边界：串首或「非字母数字下划线」的字符（消耗后在替换里回填；#133 放开冒号——「host:fe80::1」的标签形态）
		`(?:\[[0-9A-Fa-f:.%]*:[0-9A-Fa-f:.%]*:[0-9A-Fa-f:.%]*\]` + // 括号形（URL/Host 头形态，内含至少两个冒号）
		`|[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*(?:%[0-9A-Za-z._~-]+)?)`) // 裸形 + 可选 zone 后缀

// isIPv6CandByte 候选片段的首字符集（区别「左边界字符」与「候选本体」）：
// 候选只能以十六进制位、冒号、点或左括号开头。冒号有歧义（guardx#133：
// 也可能被正则当左边界消耗）——match[0]==':' 且整段判不过时，由
// maskStringLocked 剥首冒号重验消解。
func isIPv6CandByte(c byte) bool {
	switch {
	case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		return true
	case c == ':' || c == '.' || c == '[':
		return true
	}
	return false
}

// isIPv6Literal 候选片段的精确验证：剥掉括号形与 %zone 后缀后交
// net.ParseIP——候选词法保证片段至少含两个冒号，纯点分十进制的 IPv4 进不了
// 候选，故 ParseIP 判过即 IPv6（含 ::ffff:1.2.3.4 这类 v4 映射形态）。
func isIPv6Literal(cand string) bool {
	s := cand
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		s = s[1 : len(s)-1]
	}
	if i := strings.IndexByte(s, '%'); i >= 0 {
		s = s[:i]
	}
	ip := net.ParseIP(s)
	return ip != nil && ip.To16() != nil
}

// tokenRe 令牌形态（Restore 只认本包签发的全角书名号+序号）。
var tokenRe = regexp.MustCompile(`«T([0-9]+)»`)

// AddSecret 注册精确串（会话主机名、实例名等调用方已知标识），返回其令牌。空串忽略。
//
// 显式注册的串**全串盲替换**（无边界判定——调用方声明了「这个串就是凭据/
// 标识本体」，出现在任何上下文里都该被掩；长短串冲突由注册后的长度优先序
// 化解，与 logredact.RedactSecrets 同款取舍）。与动态注册（IP 模式命中）
// 的差别见 Masker.secrets：显式串参与后续精确替换，动态 IP 不参与（#122）。
func (m *Masker) AddSecret(v string) string {
	if v == "" {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.secrets[v] = true
	return m.maskLocked(v)
}

// maskLocked 注册原文→令牌（去重；同原文恒同令牌）。须持锁调用。
func (m *Masker) maskLocked(v string) string {
	if tok, ok := m.origins[v]; ok {
		return tok
	}
	m.next++
	tok := "«T" + strconv.Itoa(m.next) + "»"
	m.origins[v] = tok
	m.tokens[tok] = v
	return tok
}

// Mask 掩码文本：先精确替换显式注册串（AddSecret），再 IPv6 / IPv4 模式
// （动态注册，同址恒同令牌——且该不变量跨调用成立：早前掩过的 IP 再次出现
// 仍得同令牌，无论其后是否出现过以它为子串的更长 IP，guardx#122）。
// 结构化数据的双视图入口见 MaskValue（逐字符串值 walk，无序列化往返）。
func (m *Masker) Mask(s string) string {
	if s == "" {
		return s
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.maskStringLocked(s)
}

// Restore 回填令牌为原文（展示面专用；未知令牌原样保留）。结构化数据的
// 逆视图见 UnmaskValue。
func (m *Masker) Restore(s string) string {
	if s == "" {
		return s
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.restoreStringLocked(s)
}

// Count 已签发令牌数（测试/观测用）。
func (m *Masker) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.next
}

// MaskValue 递归掩码任意 JSON 形态值（结构化双视图，oagentkit/guardx#54）：
// 键不动、**逐字符串值**走 Mask——替代「json.Marshal → Mask → json.Unmarshal」
// 的序列化往返。往返形态的正确性依赖两个未经类型化保证的假设（令牌只在
// 字符串值里 / 字符串替换不破坏 JSON 结构），而同包 Redact 已实证结构破坏
// 面（guardx#44）——逆向 Restore 的同款结构假设不再被要求。map/slice 下探，
// 标量原样；输出的 map 为副本（不污染入参）。与 RedactValueOpts 同构的
// walk 形态，语义是 Mask（低敏感拓扑标识）不是 Redact（高敏感不回填）。
//
// 类型化容器（map[string]string / []string / []map[string]any / struct 导出
// 字段 / 指针，guardx#101）同样下探——与 #63/#76 给 RedactValue 的
// redactReflect 同源：类型开关只认 any 解码形态时，Go 侧类型化容器落
// default 原样返回，是「零令牌零报错的静默漏掩」，比它替代的序列化往返
// 更糟。边界与 redactReflect 一致：json.Number 特赦（数字字面量不是文本）、
// []byte 豁免（二进制不是文本）、未导出字段不可读原样保留、输出为副本、
// 深度上限防自引用环。
func (m *Masker) MaskValue(v any) any {
	return m.walkValue(v, maskWalk)
}

// UnmaskValue 递归回填任意 JSON 形态值中的令牌（MaskValue 的逆视图）：逐
// 字符串值 Restore，键不动、结构不动——展示面拿到的是已反序列化的结构，
// 不再有「字符串替换破坏 JSON 文本」的假设面。
func (m *Masker) UnmaskValue(v any) any {
	return m.walkValue(v, restoreWalk)
}

type walkKind int

const (
	maskWalk walkKind = iota
	restoreWalk
)

func (m *Masker) walkValue(v any, kind walkKind) any {
	switch t := v.(type) {
	case string:
		m.mu.Lock()
		defer m.mu.Unlock()
		if kind == maskWalk {
			return m.maskStringLocked(t)
		}
		return m.restoreStringLocked(t)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, vv := range t {
			out[k] = m.walkValue(vv, kind)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, vv := range t {
			out[i] = m.walkValue(vv, kind)
		}
		return out
	default:
		// 类型化容器反射下探（guardx#101）：与 redactReflect 同源——
		// map[string]string / []string / struct / 指针等 Go 侧类型化容器
		// 此前原样返回（静默漏掩）。
		return m.walkReflect(v, kind, 0)
	}
}

// walkReflect 类型化容器的反射下探（guardx#101）：语义与 redactReflect 同构，
// 叶子变换换成「掩码/回填令牌」——字符串叶子（含命名 string）过
// maskStringLocked / restoreStringLocked，map/slice/array/struct/指针/接口
// 逐层下探并保形拷贝（输出为副本，不污染入参）。与 any 形态同一份锁纪律：
// 只在字符串叶子上取 m.mu，不跨递归持锁。
//
// 刻意的边界（与 redactReflect 一致）：
//   - json.Number 特赦——命名 string 但它是数字字面量不是文本；其余命名
//     string 类型（type HostID string）仍是文本，掩码后经 Convert 还型。
//   - []byte 是二进制载荷不是文本，逐字节下探只有拷贝开销没有检测面。
//   - 未导出字段反射不可读，原样保留。
//   - 深度上限 maxWalkDepth 防类型化 Go 值的自引用环（JSON 解码值不可能
//     成环，类型化容器可以）；超限容器原样返回，字符串叶子不受影响。
func (m *Masker) walkReflect(v any, kind walkKind, depth int) any {
	rv := reflect.ValueOf(v)
	if !rv.IsValid() {
		return v
	}
	// any 形态快路径：交回类型开关，键不动/副本契约同一份实现（嵌在类型化
	// 容器里的 any 容器与顶层 any 容器行为一致）。
	switch rv.Type() {
	case mapStringAnyType, sliceAnyType:
		return m.walkValue(rv.Interface(), kind)
	}
	switch rv.Kind() {
	case reflect.String:
		if rv.Type() == jsonNumberType {
			return v
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		if kind == maskWalk {
			return m.maskStringLocked(rv.String())
		}
		return m.restoreStringLocked(rv.String())
	case reflect.Map:
		if rv.IsNil() || depth >= maxWalkDepth {
			return v
		}
		out := reflect.MakeMapWithSize(rv.Type(), rv.Len())
		it := rv.MapRange()
		for it.Next() {
			out.SetMapIndex(it.Key(), m.walkAssignable(it.Value(), rv.Type().Elem(), kind, depth+1))
		}
		return out.Interface()
	case reflect.Slice, reflect.Array:
		if (rv.Kind() == reflect.Slice && rv.IsNil()) || depth >= maxWalkDepth {
			return v
		}
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			return v // []byte：二进制载荷不是文本
		}
		var out reflect.Value
		if rv.Kind() == reflect.Slice {
			out = reflect.MakeSlice(rv.Type(), rv.Len(), rv.Len())
		} else {
			out = reflect.New(rv.Type()).Elem()
			out.Set(rv)
		}
		for i := range rv.Len() {
			out.Index(i).Set(m.walkAssignable(rv.Index(i), rv.Type().Elem(), kind, depth+1))
		}
		return out.Interface()
	case reflect.Struct:
		if depth >= maxWalkDepth {
			return v
		}
		t := rv.Type()
		out := reflect.New(t).Elem()
		out.Set(rv) // 先整体拷贝再覆写下探结果：未导出字段与无需处理的原样保留
		for i := range t.NumField() {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			out.Field(i).Set(m.walkAssignable(rv.Field(i), f.Type, kind, depth+1))
		}
		return out.Interface()
	case reflect.Pointer:
		if rv.IsNil() {
			return v
		}
		walked := m.walkReflect(rv.Elem().Interface(), kind, depth+1)
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
		return m.walkReflect(rv.Elem().Interface(), kind, depth+1)
	default:
		return v
	}
}

// walkAssignable 下探后回填到目标元素/字段类型（与 jsonredact.go 的
// walkAssignable 同型）：掩码/回填叶子返回裸 string，命名 string 目标经
// Convert 还型（type HostID string 的字段掩码后仍是 HostID）；nil 接口叶子
// 取目标零值；理论不可达的类型失配兜底取原值（宁可不改，不让掩码链路 panic）。
func (m *Masker) walkAssignable(val reflect.Value, dst reflect.Type, kind walkKind, depth int) reflect.Value {
	var walked any
	switch {
	case val.Kind() == reflect.Interface && !val.IsNil():
		walked = m.walkReflect(val.Elem().Interface(), kind, depth)
	case val.Kind() != reflect.Interface:
		walked = m.walkReflect(val.Interface(), kind, depth)
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

// maskStringLocked / restoreStringLocked 单值操作体（walk 持锁入口拆分）：
// 逻辑与 Mask/Restore 同源（精确串长优先 + IPv6/IPv4 动态注册 / 令牌回填）。
//
// 精确阶段只处理 AddSecret 显式串（#122）：动态注册的 IP 原文不再做盲替换
// ——它们再次出现时由下方 IP 模式重新整段命中（maskLocked 去重 ⇒ 同址恒同
// 令牌跨调用成立）。此前对全部 origins 盲替换的缺陷：先 Mask 短 IP（动态
// 注册）再 Mask 以它为中部子串的长 IP（11.2.3.4 含 1.2.3.4），长 IP 被换成
// 「1«Tn»」残段——既非原址形态、令牌外残留原文，还污染下游按 «Tn» 形态
// 消费令牌的 Count/UnmaskValue/报告渲染。
func (m *Masker) maskStringLocked(s string) string {
	if s == "" {
		return s
	}
	origins := make([]string, 0, len(m.secrets))
	for origin := range m.secrets {
		if origin != "" {
			origins = append(origins, origin)
		}
	}
	slices.SortFunc(origins, func(a, b string) int { return cmp.Compare(len(b), len(a)) })
	for _, origin := range origins {
		s = strings.ReplaceAll(s, origin, m.origins[origin])
	}
	// IPv6 先于 IPv4（#100）：v4 映射/NAT64 形态（::ffff:10.0.0.5、
	// 64:ff9b::192.0.2.33）是**一个** IPv6 字面量，先整段掩掉；若 IPv4 先行，
	// 内嵌的 v4 段先被换成令牌，整段形态就被破坏、IPv6 判定无从做起了。
	s = ipv6Re.ReplaceAllStringFunc(s, func(match string) string {
		cand := match
		prefix := ""
		if !isIPv6CandByte(match[0]) {
			prefix, cand = match[:1], match[1:] // 左边界字符（正则消耗掉的），回填
		} else if match[0] == ':' && !isIPv6Literal(match) && isIPv6Literal(match[1:]) {
			// 冒号放开后身兼两职（guardx#133）：既是合法候选首字符（::1），
			// 又可作为左边界（host:fe80::1 的标签冒号）。整段判不过、剥掉
			// 首个冒号判得过 ⇒ 该冒号是标签边界不是候选本体——剥掉回填。
			// 真负例（12:30:45、MAC）剥后仍判不过，原样保留。
			prefix, cand = match[:1], match[1:]
		}
		trailing := ""
		if !isIPv6Literal(cand) {
			// 句点紧跟地址（"gateway is ::1."）是 prose 常态：候选贪吃进
			// 了句点导致 ParseIP 判负——剥尾点重验，剥得动且判过就掩地址、
			// 保留句点；仍判不过就是非地址（时刻/MAC/作用域符），原样保留。
			if t := strings.TrimRight(cand, "."); t != cand && isIPv6Literal(t) {
				trailing, cand = cand[len(t):], t
			} else {
				return match
			}
		}
		return prefix + m.maskLocked(cand) + trailing
	})
	return ipv4Re.ReplaceAllStringFunc(s, func(match string) string {
		return m.maskLocked(match)
	})
}

func (m *Masker) restoreStringLocked(s string) string {
	if s == "" {
		return s
	}
	return tokenRe.ReplaceAllStringFunc(s, func(tok string) string {
		if v, ok := m.tokens[tok]; ok {
			return v
		}
		return tok
	})
}
