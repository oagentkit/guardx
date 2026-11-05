package logredact

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Masker 低敏感掩码+令牌回填器（K8sGPT anonymize 形态，bianque spec
// 2026-09-14-aiops-uplift-design §3）：把目标机拓扑标识（IPv4 + 调用方注册的精确串）
// 在进 LLM 前替换为 «Tn» 令牌，在最终展示面 Restore 回填原名——LLM 解释里引用的
// 「主机 «T1»」在报告中还原为真名，可读性与隐私兼得。
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
}

// NewMasker 构造（零值不可用，一律经本构造）。
func NewMasker() *Masker {
	return &Masker{tokens: map[string]string{}, origins: map[string]string{}}
}

// ipv4Re 低敏感默认模式：IPv4 地址（工具输出里最常见的拓扑标识）。
var ipv4Re = regexp.MustCompile(`\b(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b`)

// tokenRe 令牌形态（Restore 只认本包签发的全角书名号+序号）。
var tokenRe = regexp.MustCompile(`«T([0-9]+)»`)

// AddSecret 注册精确串（会话主机名、实例名等调用方已知标识），返回其令牌。空串忽略。
func (m *Masker) AddSecret(v string) string {
	if v == "" {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
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

// Mask 掩码文本：先精确注册串，再 IPv4 模式（动态注册，同址恒同令牌）。
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
		return v
	}
}

// maskStringLocked / restoreStringLocked 单值操作体（walk 持锁入口拆分）：
// 逻辑与 Mask/Restore 同源（精确串长优先 + IPv4 动态注册 / 令牌回填）。
func (m *Masker) maskStringLocked(s string) string {
	if s == "" {
		return s
	}
	origins := make([]string, 0, len(m.origins))
	for origin := range m.origins {
		if origin != "" {
			origins = append(origins, origin)
		}
	}
	sort.Slice(origins, func(i, j int) bool { return len(origins[i]) > len(origins[j]) })
	for _, origin := range origins {
		s = strings.ReplaceAll(s, origin, m.origins[origin])
	}
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
