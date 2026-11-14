// guardx#176 双模式与可配掩码回归：ValueOptions 增 Mask / KeyTokens /
// KeyMode（KeyMatchSegment 分段（零值默认）/ KeyMatchExact 精确收窄 /
// KeyMatchSubstring 子串），收编 bianque internal/redact 的 ExactKey /
// LooseKey 两套键名谓词与可配打码体，下游不再为「精确 vs 子串」「掩码
// 字面量」各写一份绕行脱敏器。
package logredact

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// auditFaceTokens 代表 bianque 审计面迁移前 LooseKey 正则的词表（子串口径、
// 逐字对齐的字面子串集——#176 (b)：audit_svc.go / webhook_svc.go 两消费点）。
// 实证差异对比（(e) 的证据义务）用它对内置分段口径逐键对照，见
// TestIssue176SubstringVsSegmentDiff。
var auditFaceTokens = []string{"password", "secret", "token", "api_key", "authorization", "credential"}

// leakSample 不命中任何文本规则的普通字符串值——键名面是否打码可以直接从
// 输出读出（值原文 vs "****"/自定义打码体）。
const leakSample = "leaked-secret-value-123"

// hitKey 在 opts 口径下 key 是否整值打码（false = 值原文透传）。
func hitKey(t *testing.T, key string, opts ValueOptions) bool {
	t.Helper()
	out := RedactValueOpts(map[string]any{key: leakSample}, opts)
	m, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("map 形态应原路返回，实得 %T", out)
	}
	return m[key] != leakSample
}

// TestIssue176DefaultUnchanged 零值 ValueOptions 行为与 #176 之前逐键一致
// （默认不变是 (e) 的硬要求）：内置分段词表照常命中，宿主词元表为空不参与。
func TestIssue176DefaultUnchanged(t *testing.T) {
	for _, key := range []string{"password", "api_key", "authorization", "password_hash"} {
		if !hitKey(t, key, ValueOptions{}) {
			t.Errorf("零值选项下键 %q 应照常整值打码（默认行为不变）", key)
		}
	}
	if hitKey(t, "prompt_tokens", ValueOptions{}) {
		t.Error("prompt_tokens 默认不打码（guardx#52 契约，零值不得松动）")
	}
	// 中性键照旧（#178 已知代价：sort_key 因 keys? 收编命中——该口径不因本单变化）。
	if !hitKey(t, "sort_key", ValueOptions{}) {
		t.Error("sort_key 默认应照旧命中（#178 口径不变）")
	}
}

// TestIssue176Mask 打码体可配（#176 ①）：审计面约定 "***"，此前 maskLiteral
// 硬编码 const 无法表达。空串回落内置 "****"（忘填 = 空掩码的静默失效被
// 回落挡住）。掩码只作用于键名面整值打码，字符串叶子内的内嵌凭据仍由文本
// 规则打码（掩码字面由规则 Repl 决定）。
func TestIssue176Mask(t *testing.T) {
	out := RedactValueOpts(map[string]any{"password": leakSample, "note": "see password=abc123"}, ValueOptions{Mask: "***"})
	m := out.(map[string]any)
	if m["password"] != "***" {
		t.Errorf("凭证键打码体应为 opts.Mask：实得 %v", m["password"])
	}
	// 叶子内嵌凭据仍走文本规则（"****"），Mask 不改文本面。
	if !strings.Contains(m["note"].(string), "password=****") {
		t.Errorf("叶子内嵌凭据仍应由文本规则打码: %v", m["note"])
	}
	// JSON 面同样生效。
	j := RedactJSONOpts([]byte(`{"audit_secret":"v"}`), ValueOptions{Mask: "***", KeyTokens: []string{"secret"}, KeyMode: KeyMatchSubstring})
	if !strings.Contains(string(j), `"audit_secret":"***"`) {
		t.Errorf("JSON 面打码体应为 opts.Mask: %s", j)
	}
	// 空串回落内置。
	if out := RedactValueOpts(map[string]any{"password": leakSample}, ValueOptions{Mask: ""}); out.(map[string]any)["password"] != maskLiteral {
		t.Errorf("Mask 空串应回落内置 %s", maskLiteral)
	}
	// 类型化容器：命名 string 字段经 Convert 还型且打码体可配。
	type rec struct {
		APIKey passWord `json:"api_key"`
	}
	out = RedactValueOpts(rec{APIKey: leakSample}, ValueOptions{Mask: "***"})
	if got := out.(rec).APIKey; got != "***" {
		t.Errorf("struct 命名 string 字段打码体应为 opts.Mask：实得 %q", got)
	}
}

// passWord 测试用命名 string（模拟 type Password string）。
type passWord string

// TestIssue176SegmentUnion 分段口径（零值默认）：宿主词元与内置词表**并集**
// （叠加语义，内置保护不松动）；词元按段语义命中——任意位起 + [_-] 分隔
// 后续段到键尾（#132 口径），多段词元的分隔符放开为 [_-]。
func TestIssue176SegmentUnion(t *testing.T) {
	opts := ValueOptions{KeyTokens: []string{"trace_secret", "db_token"}}
	for _, key := range []string{
		"trace_secret",    // 词元本身
		"x-trace-secret",  // kebab 段（多段词元分隔符放开 [_-]）
		"trace_secret_id", // 后续段（#132：词元可在任意段）
		"mytrace_secret",  // 前缀直连（内置表 mypassword 同款）
		"db_token",        // 多段词元本身
		"authorization",   // 内置词表照常（并集）
	} {
		if !hitKey(t, key, opts) {
			t.Errorf("分段口径并集下 %q 应命中", key)
		}
	}
	// 词元按字面不带复数/计量收窄展开（那是内置表的形态学，不是宿主词表的）：
	// "db_token" 分段不吃 "db_tokens"（复数请自行列入词元表）；内置表按 #52
	// 收窄也不命中 "prompt_tokens"——计量面契约不因宿主词元松动。
	for _, key := range []string{"db_tokens", "prompt_tokens"} {
		if hitKey(t, key, opts) {
			t.Errorf("分段口径不应命中 %q（复数/计量收窄是内置表契约，词元表按字面）", key)
		}
	}
	// 中性键不被宿主词元误吞。
	if hitKey(t, "sort_field", opts) {
		t.Error("sort_field 不应命中")
	}
}

// TestIssue176ExactNarrow 精确收窄口径（显式 opt-in，guardx#176 ②/(e)）：
// 只打恰等于词元的键，内置词表**整体退出**——收窄模式被显式选择后的字面
// 语义，本测试把它钉住（含风险面：通用凭证词不在词元表即不打码）。
func TestIssue176ExactNarrow(t *testing.T) {
	opts := ValueOptions{KeyMode: KeyMatchExact, KeyTokens: []string{"Secret", "session_token "}}
	for _, key := range []string{"secret", " SECRET ", "secret "} {
		if !hitKey(t, key, opts) {
			t.Errorf("精确口径应双侧归一命中 %q", key)
		}
	}
	if !hitKey(t, "session_token", opts) {
		t.Error("词元首尾空白应归一")
	}
	// 收窄面：分段命中、前后缀扩展、内置词表全部退出。
	for _, key := range []string{"my_secret", "secret_hash", "api_key", "password", "authorization"} {
		if hitKey(t, key, opts) {
			t.Errorf("精确收窄不应命中 %q（内置词表已退出——显式 opt-in 的字面语义）", key)
		}
	}
	// IsCredentialKey 回调在收窄模式下仍叠加（回调恒为追加语义）。
	opts2 := ValueOptions{
		KeyMode:         KeyMatchExact,
		KeyTokens:       []string{"secret"},
		IsCredentialKey: func(key string) bool { return key == "custom_metric_key" },
	}
	if !hitKey(t, "custom_metric_key", opts2) {
		t.Error("收窄模式下回调应照常叠加")
	}
	// 空词元表 + 无回调 = 收窄到空集：显式配置的字面语义（不打任何键）。
	if hitKey(t, "password", ValueOptions{KeyMode: KeyMatchExact}) {
		t.Error("空词元表收窄到空集应不打码（显式即责任的字面语义）")
	}
}

// TestIssue176SubstringUnion 子串口径（审计面 LooseKey 迁移）：归一键**包含**
// 词元即命中，比分段宽（over-mask 方向）；内置词表照常并集。
func TestIssue176SubstringUnion(t *testing.T) {
	opts := ValueOptions{KeyMode: KeyMatchSubstring, KeyTokens: auditFaceTokens}
	for _, key := range []string{
		"mypassword1",     // 子串命中（分段失配——迁移前正则命中面）
		"passwordx",       // 同上
		"MyAuthorization", // 大写归一
		"x-api-key",       // kebab（内置词表的 [_-]? 弹性，并集照常）
		"user_passwords",  // 复数
	} {
		if !hitKey(t, key, opts) {
			t.Errorf("子串口径下 %q 应命中", key)
		}
	}
	// 未知词不误吞（子串词表外的中性键）。
	if hitKey(t, "sort_field", opts) {
		t.Error("sort_field 不应命中")
	}
}

// TestIssue176SubstringVsSegmentDiff guardx#176 (e) 的实证差异对比：审计面
// 迁移前正则（LooseKey **纯子串**口径）命中面 vs **纯宿主分段**口径命中面
// 逐键对照（两列都走 hostKeyMatch，只看宿主词元层，不含内置表——迁移前后
// 的口径差就是这样逐键可验）。
//
// 结论钉在这里：子串 ⊋ 分段，主差集是「词元后直连字母/数字」的复合形态
// （mypassword1 / passwordx / secret1 / tokens 复数）——按分段口径迁入会漏掉
// 差集里的每一个键，这是 KeyMatchSubstring 必须存在的实证依据。迁移后的
// 实际命中面 = 内置表 ∪ 宿主子串（见末段断言）：内置侧自带加宽（sort_key
// 经 #178 keys? 命中、passwords 复数展开），两个方向都只宽不窄（over-mask
// 方向，与凭证词表吞 bypass 的取舍同款），内置保护不松动。
//
// 本表就是「内置分段已够」反驳意见的实证回答（#176 (e) 证据义务）。
func TestIssue176SubstringVsSegmentDiff(t *testing.T) {
	// 逐键期望：(key, 迁移前纯子串命中, 纯宿主分段命中, 说明)。
	cases := []struct {
		key     string
		loose   bool
		segment bool
		why     string
	}{
		{"password", true, true, "词元本身"},
		{"db_password", true, true, "分隔段前缀"},
		{"user_password_hash", true, true, "#132：词元在中间 + 后续段"},
		{"passwords", true, false, "★差集：词元按字面无复数展开（复数请自行列入词元表）"},
		{"mypassword1", true, false, "★差集：词元后直连数字，分段失配"},
		{"passwordx", true, false, "★差集：词元后直连字母（passwordless 家族，分段刻意放过）"},
		{"secret1", true, false, "★差集：同款"},
		{"tokens", true, false, "★差集：裸复数（分段按字面失配）"},
		{"sort_key", false, false, "宿主词元表两侧都不命中（裸 key 不在审计面词表）"},
		{"sort_field", false, false, "两侧都不命中（中性键）"},
	}
	for _, c := range cases {
		loose := hostKeyMatch(c.key, ValueOptions{KeyMode: KeyMatchSubstring, KeyTokens: auditFaceTokens})
		seg := hostKeyMatch(c.key, ValueOptions{KeyTokens: auditFaceTokens})
		if loose != c.loose || seg != c.segment {
			t.Errorf("键 %q：纯子串=%v 纯分段=%v，应 (loose=%v, segment=%v)——%s", c.key, loose, seg, c.loose, c.segment, c.why)
		}
	}
	// 迁移后的实际命中面（并集）＝内置表 ∪ 宿主子串：差集键兜住（不漏），
	// 内置侧自带加宽照常（sort_key 经 #178 keys? 命中）。
	for _, key := range []string{"mypassword1", "passwordx", "secret1", "tokens", "sort_key"} {
		if !hitKey(t, key, ValueOptions{KeyMode: KeyMatchSubstring, KeyTokens: auditFaceTokens}) {
			t.Errorf("并集迁移口径下 %q 必须命中（不漏）", key)
		}
	}
}

// TestIssue176ExtraRulesStillApply ExtraRules 与新模式正交：值模式扩展规则
// 照常并入字符串叶子（#176「词元表支持 ExtraRules 并入」的字面要求）。
func TestIssue176ExtraRulesStillApply(t *testing.T) {
	opts := ValueOptions{
		KeyMode:   KeyMatchExact,
		KeyTokens: []string{"phone"},
		ExtraRules: []Rule{{
			Name: "cn-mobile",
			Re:   regexp.MustCompile(`1[3-9]\d{9}`),
			Repl: "****",
		}},
	}
	out := RedactValueOpts(map[string]any{
		"phone":  "leak",
		"mobile": "13800138000", // 键不在词元表，值模式规则兜
	}, opts)
	m := out.(map[string]any)
	if m["phone"] != "****" {
		t.Errorf("精确口径词元键应整值打码: %v", m["phone"])
	}
	if m["mobile"] != "****" {
		t.Errorf("ExtraRules 值模式应照常生效: %v", m["mobile"])
	}
}

// TestIssue176MaskTypedContainers 类型化容器（#63/#76 反射面）与新选项同一
// 口径：map[string]string / slice/struct 下探、命中键整值打码、打码体可配、
// 收窄模式同样生效、输出为副本。
func TestIssue176MaskTypedContainers(t *testing.T) {
	in := map[string]string{"db_secret": leakSample, "keep": "1"}
	out := RedactValueOpts(in, ValueOptions{Mask: "***", KeyTokens: []string{"secret"}, KeyMode: KeyMatchSubstring})
	m := out.(map[string]string)
	if m["db_secret"] != "***" || m["keep"] != "1" {
		t.Fatalf("map[string]string 下探打码体应为 opts.Mask: %v", m)
	}
	if in["db_secret"] != leakSample {
		t.Fatal("入参不得被改写（#63 契约）")
	}
	type nested struct {
		Items []map[string]any `json:"items"`
	}
	n := nested{Items: []map[string]any{{"trace_secret": leakSample}}}
	got := RedactValueOpts(n, ValueOptions{Mask: "***", KeyTokens: []string{"secret"}, KeyMode: KeyMatchSubstring}).(nested).Items[0]["trace_secret"]
	if got != "***" {
		t.Fatalf("slice/struct 下探应同口径: %v (%T)", got, got)
	}
	// maskValueFor 对命名 string 目标的 Convert 还型（掩码后仍是 Password 类型）。
	type rec struct {
		Password passWord `json:"password"`
	}
	if r := RedactValueOpts(rec{Password: "x"}, ValueOptions{Mask: "***"}).(rec); r.Password != "***" {
		t.Fatalf("命名 string 字段应 Convert 还型: %q", r.Password)
	}
}

// TestIssue176JSONRoundTrip JSON 面端到端：合法 JSON 结构保住、Mask 与
// KeyMode 组合生效；非法 JSON 回落文本规则不受新选项影响（Mask 只管键名面）。
func TestIssue176JSONRoundTrip(t *testing.T) {
	opts := ValueOptions{Mask: "***", KeyMode: KeyMatchSubstring, KeyTokens: auditFaceTokens}
	in := []byte(`{"audit_password":"abc","note":"user_password1 in prose","count":3}`)
	out := RedactJSONOpts(in, opts)
	if !json.Valid(out) {
		t.Fatalf("输出必须恒为合法 JSON: %s", out)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if m["audit_password"] != "***" || m["note"] != "user_password1 in prose" || m["count"] != float64(3) {
		t.Fatalf("JSON 面语义不符: %v", m)
	}
	// 非法 JSON 回落文本规则（Mask/KeyMode 不影响文本面）。
	fallback := RedactJSONOpts([]byte(`password=abc123 x`), opts)
	if !strings.Contains(string(fallback), "password=****") || strings.Contains(string(fallback), "abc123") {
		t.Fatalf("非法 JSON 应回落文本规则: %s", fallback)
	}
}
