package logredact

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	cases := []struct{ in, want, mustNotContain string }{
		{
			in:             "NATS 已连接: nats://ops:s3cret@10.0.0.5:4222",
			want:           "nats://ops:****@10.0.0.5:4222",
			mustNotContain: "s3cret",
		},
		{
			in:             "dsn=postgres://user:pass@127.0.0.1:5432/db?sslmode=disable",
			want:           "postgres://user:****@127.0.0.1:5432/db?sslmode=disable",
			mustNotContain: ":pass@",
		},
		{
			in:             "webhook https://example.com/send?key=ABC123-xyz sent",
			want:           "key=****",
			mustNotContain: "ABC123",
		},
		{
			// v0.14.0：auth 入词表 + bearer 组先行——scheme 与凭据体一起收敛为
			// 单段掩码（kv 裸值吞 `Bearer <已掩码体>`，不留孤儿段）
			in:             "auth=Bearer eyJhbGciOiJIUzI1NiJ9.e30.sig",
			want:           "auth=****",
			mustNotContain: "eyJhbGciOiJIUzI1NiJ9",
		},
		{
			in:             "password=hunter2 user=bob",
			want:           "password=**** user=bob",
			mustNotContain: "hunter2",
		},
		{
			// 凭证词键值对容忍 ": " 空格形态（kubeconfig/私钥 YAML 日志常见）；
			// v0.14.0 起分隔符保形——原样保留「: 」不再吞成「=」（guardx#44）
			in:             "private-key: MIIEvQIBADANBgkq",
			want:           "private-key: ****",
			mustNotContain: "MIIEvQ",
		},
		{
			in:             "kubeconfig = /home/u/.kube/config with secret-key: abc123",
			want:           "secret-key: ****",
			mustNotContain: "abc123",
		},
		{
			// PEM 私钥整段打码
			in:             "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\nasdf\n-----END RSA PRIVATE KEY-----",
			want:           "----PRIVATE KEY ****",
			mustNotContain: "MIIEow",
		},
		{
			// 散文中的普通键值不受凭证词表误伤
			in:   "user-keynote: 演讲主题",
			want: "user-keynote: 演讲主题",
		},
	}
	for _, c := range cases {
		got := Redact(c.in)
		if !strings.Contains(got, c.want) {
			t.Errorf("Redact(%q) = %q, 期望含 %q", c.in, got, c.want)
		}
		if c.mustNotContain != "" && strings.Contains(got, c.mustNotContain) {
			t.Errorf("Redact(%q) = %q, 泄漏 %q", c.in, got, c.mustNotContain)
		}
	}

	for _, plain := range []string{
		"会话 sess-0908-abc succeeded",
		"知识库已索引: dir=knowledge",
		"地址 http://127.0.0.1:8900",
	} {
		if got := Redact(plain); got != plain {
			t.Errorf("无凭据文本不应改动: %q → %q", plain, got)
		}
	}
}

func TestRedactValue(t *testing.T) {
	in := map[string]any{
		"dsn":    "postgres://u:p@h/db",
		"nested": map[string]any{"auth": "Bearer tok.en.sig"},
		"list":   []any{"token=abc", 42},
		"ok":     "safe",
	}
	out, _ := RedactValue(in).(map[string]any)
	if s, _ := out["dsn"].(string); strings.Contains(s, ":p@") {
		t.Errorf("dsn 未脱敏: %q", s)
	}
	nested, _ := out["nested"].(map[string]any)
	if s, _ := nested["auth"].(string); strings.Contains(s, "tok.en") {
		t.Errorf("nested auth 未脱敏: %q", s)
	}
	list, _ := out["list"].([]any)
	if s, _ := list[0].(string); strings.Contains(s, "abc") {
		t.Errorf("list[0] 未脱敏: %q", s)
	}
	if list[1] != 42 {
		t.Errorf("非字符串应原样保留: %v", list[1])
	}
	if out["ok"] != "safe" {
		t.Errorf("无凭据字段不应改动: %v", out["ok"])
	}
}

// TestRedactValueKeyedMasking 回归（guardx#44 同源缺陷）：解码后的字符串值
// 失去键上下文，文本规则认不出——`{"password": "abc123"}` 此前原样透传。
// 键感知打码：凭证词键的整值打码，无论原值形态。
func TestRedactValueKeyedMasking(t *testing.T) {
	in := map[string]any{
		"password": "abc123",
		"apiKey":   "sk-abcdefghijklmnopqrst",
		"retries":  3,
		"deep":     map[string]any{"client_secret": map[string]any{"v": "xyz"}},
		"list":     []any{"pwd=abc123", "safe"},
	}
	out, _ := RedactValue(in).(map[string]any)
	if out["password"] != "****" {
		t.Errorf("凭证词键的值应整值打码: %v", out["password"])
	}
	if out["apiKey"] != "****" {
		t.Errorf("camelCase 凭证键应命中: %v", out["apiKey"])
	}
	if out["retries"] != 3 {
		t.Errorf("非凭证键的标量应原样: %v", out["retries"])
	}
	deep, _ := out["deep"].(map[string]any)
	if deep["client_secret"] != "****" {
		t.Errorf("嵌套凭证键应整值打码（对象形态也不留绕过缝）: %v", deep["client_secret"])
	}
	list, _ := out["list"].([]any)
	if s, _ := list[0].(string); strings.Contains(s, "abc123") {
		t.Errorf("数组内文本形态应过文本规则: %q", s)
	}
	if list[1] != "safe" {
		t.Errorf("安全文本应原样: %v", list[1])
	}
	// 中性键不误伤
	out2, _ := RedactValue(map[string]any{"sort_key": "name", "authorized_keys": "/home"}).(map[string]any)
	if out2["sort_key"] != "name" || out2["authorized_keys"] != "/home" {
		t.Errorf("中性键误伤: %v", out2)
	}
}

// TestRedactJSON 回归（guardx#44 结构化路径）：合法 JSON 走键感知结构化打码，
// 输出恒为合法 JSON；非法 JSON 回落文本规则。
func TestRedactJSON(t *testing.T) {
	// 键感知整值打码 + 字符串值文本规则 + 数字保形
	in := []byte(`{"api_key": "sk-123", "dsn": "postgres://u:pw@h/db", "n": 3, "big": 12345678901234567890}`)
	out := RedactJSON(in)
	if !json.Valid(out) {
		t.Fatalf("输出非法 JSON: %s", out)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	if m["api_key"] != "****" {
		t.Errorf("凭证键未整值打码: %v", m["api_key"])
	}
	if s, _ := m["dsn"].(string); strings.Contains(s, "pw@") {
		t.Errorf("内嵌连接串未过文本规则: %q", s)
	}
	if m["n"] != float64(3) {
		t.Errorf("数字应保形: %v", m["n"])
	}
	// 大整数精度：json.Number 通道保字面量
	if !strings.Contains(string(out), "12345678901234567890") {
		t.Errorf("大整数应保字面量: %s", out)
	}
	// 数组/嵌套
	out = RedactJSON([]byte(`{"users":[{"api_key":"sk-1"},{"pwd":"p2"}]}`))
	if !json.Valid(out) || strings.Contains(string(out), "sk-1") || strings.Contains(string(out), `"p2"`) {
		t.Errorf("嵌套凭证键未打码或结构破坏: %s", out)
	}
	// 非法 JSON 回落文本规则
	fallback := RedactJSON([]byte(`log pwd=abc123 tail`))
	if !strings.Contains(string(fallback), "pwd=****") || strings.Contains(string(fallback), "abc123") {
		t.Errorf("非法 JSON 应回落文本规则: %q", fallback)
	}
	// 幂等
	once := RedactJSON([]byte(`{"password": "abc", "note": "token=abc"}`))
	twice := RedactJSON(once)
	if string(twice) != string(once) {
		t.Errorf("RedactJSON 应幂等:\n once=%s\ntwice=%s", once, twice)
	}
}

func TestRedactSecrets(t *testing.T) {
	// 精确串抹除（高敏感已知名单——与模式化 Redact 互补，与 Masker 相反不回填）。
	got := RedactSecrets("clone https://oauth2:tok123@host/r.git 失败: tok123", "tok123")
	if strings.Contains(got, "tok123") {
		t.Fatalf("秘密未抹除: %s", got)
	}
	if !strings.Contains(got, "oauth2:***@") {
		t.Fatalf("URL 形态应保持可读: %s", got)
	}
	// 长秘密优先：短串是长串前缀时，先替短串会留下尾段泄漏。
	got = RedactSecrets("k=abcdef k2=abc", "abc", "abcdef")
	if strings.Contains(got, "def") || strings.Contains(got, "abc") {
		t.Fatalf("长串优先替换防尾段泄漏: %s", got)
	}
	// 空串忽略、无命中原样返回。
	if got := RedactSecrets("plain", "", "nohit"); got != "plain" {
		t.Fatalf("无命中应原样返回: %s", got)
	}
}

// 平台 API token 特征前缀（裸形态）打码——2026-09 review-service 收敛评估反哺：
// 旧规则只覆盖键值对/连接串形态，裸 token 散文形态（sk-/ghp_/JWT）会泄漏。
func TestRedactProviderTokenPrefixes(t *testing.T) {
	cases := []struct{ name, in, mustNotContain string }{
		{"OpenAI 风格", "key is sk-abc123def456ghi789jklmnop", "sk-abc123"},
		{"Anthropic 风格", "sk-ant-api03-abcdef1234567890abcdef", "sk-ant-api03"},
		{"GitHub PAT", "push with ghp_0123456789abcdefghij", "ghp_0123456789"},
		{"Slack", "xoxb-123456789012-abcdef", "xoxb-123456789012"},
		{"AWS AKIA", "aws key AKIAIOSFODNN7EXAMPLE in log", "AKIAIOSFODNN7EXAMPLE"},
		{"JWT", "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c leaked", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIi"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Redact(c.in)
			if strings.Contains(got, c.mustNotContain) {
				t.Fatalf("泄漏未打码: %q -> %q", c.in, got)
			}
		})
	}
}

func TestRedactKeepsNormalText(t *testing.T) {
	// 防误伤：普通文本/路径/短词不受新规则影响。
	normal := "task done in 1.25s, see design.md and http://example.com/docs"
	if got := Redact(normal); got != normal {
		t.Fatalf("普通文本被误改: %q -> %q", normal, got)
	}
}

// TestRedactAuthorizationHeader 回归（第九轮审计 C 级）：Authorization 头的
// 凭据本体必须整体打码——此前规则只吃 scheme 名（\S+），Basic/Bearer 后的
// base64/裸 token 原文泄漏，且 Bearer 规则失去锚点兜不住。
func TestRedactAuthorizationHeader(t *testing.T) {
	cases := []struct{ in, cred string }{
		{"Authorization: Basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA=="},
		{"Authorization: Bearer gf7t2xK9randomOpaqueToken0a1b2c", "gf7t2xK9randomOpaqueToken0a1b2c"},
		{"authorization=bearer-cred-abcdef0123456789", "bearer-cred-abcdef0123456789"},
	}
	for _, c := range cases {
		out := Redact(c.in)
		if strings.Contains(out, c.cred) {
			t.Errorf("%q 凭据泄漏: %q", c.in, out)
		}
	}
}

// TestRedactPasswordColonSpace 回归（第九轮审计）：YAML/缩进 JSON 的
// `password: xxx` 形态（冒号后空格）必须打码。
func TestRedactPasswordColonSpace(t *testing.T) {
	for _, in := range []string{
		"password: hunter2",
		"  token: abc.def.ghi12345",
		`{"password": "s3cr3tVALUE"}`,
	} {
		out := Redact(in)
		for _, cred := range []string{"hunter2", "abc.def.ghi12345", "s3cr3tVALUE"} {
			if strings.Contains(out, cred) {
				t.Errorf("%q 凭据泄漏: %q", in, out)
			}
		}
	}
}

// TestRedactModernTokenPrefixes 回归（第九轮审计）：sk-proj-（OpenAI 现行）、
// mongodb+srv://、amqps:// 形态覆盖。
func TestRedactModernTokenPrefixes(t *testing.T) {
	out := Redact("key=sk-proj-abcdef0123456789abcdef0123456789abcd")
	if strings.Contains(out, "sk-proj-abcdef") {
		t.Errorf("sk-proj- 泄漏: %q", out)
	}
	out = Redact("connect mongodb+srv://user:passw0rd@cluster.example.net/")
	if strings.Contains(out, "passw0rd") {
		t.Errorf("mongodb+srv 凭据泄漏: %q", out)
	}
}

// TestRedactTruncatedPEM 回归（第九轮审计）：日志截断落在 PEM 中段（BEGIN
// 无 END）时私钥体不泄漏。
func TestRedactTruncatedPEM(t *testing.T) {
	in := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7xK9tG\n(truncated"
	out := Redact(in)
	if strings.Contains(out, "MIIEowIBAAKCAQEA7xK9tG") {
		t.Errorf("截断 PEM 泄漏: %q", out)
	}
}

// TestRedactCompoundKeysAndQuotedValues 回归（第十轮审计）：
// ① snake_case/camelCase 复合键（admin_password:/openai_api_key:/authToken:）
//
//	——\b 词边界把下划线/驼峰前缀挡住，此前整体漏网；
//
// ② 引号多词值（passphrase: "correct horse battery staple"）——值字符集
//
//	排除空白，此前只打码首词、尾段泄漏。
func TestRedactCompoundKeysAndQuotedValues(t *testing.T) {
	cases := []struct{ in, cred string }{
		{"admin_password: hunter2", "hunter2"},
		{"openai_api_key: mysecret123", "mysecret123"},
		{"authToken: abc.def.ghi", "abc.def.ghi"},
		{`passphrase: "correct horse battery staple"`, "correct horse battery staple"},
		{`{"db_password": "p@ss w0rd"}`, "p@ss w0rd"},
	}
	for _, c := range cases {
		out := Redact(c.in)
		if strings.Contains(out, c.cred) {
			t.Errorf("%q 凭据泄漏: %q", c.in, out)
		}
	}
}

// TestRedactPwdAbbreviations 回归（guardx#45）：pwd/pass/auth 等常见缩写与
// 复数形态此前不在词表——`pwd=abc123` 原样泄漏（passwd 命中、pwd 不命中）。
// 值模式脱敏的承诺是「键表内的键，值必被打码」，键表覆盖面就是这个承诺的边界。
func TestRedactPwdAbbreviations(t *testing.T) {
	for _, in := range []string{
		"pwd=abc123",
		"pwd: hunter2",
		"pass: hunter2",
		`{"pwd": "s3cr3t"}`,
		`{"client_secret": "cs_live_abc123"}`,
		"auth=opaque-credential-987654",
		"passwords=a b", // 复数形态
	} {
		out := Redact(in)
		if strings.Contains(out, "abc123") || strings.Contains(out, "hunter2") ||
			strings.Contains(out, "s3cr3t") || strings.Contains(out, "cs_live_abc123") ||
			strings.Contains(out, "opaque-credential-987654") {
			t.Errorf("%q 凭据泄漏: %q", in, out)
		}
	}
	// 已知代价（词表注释）：以 pass 结尾的普通词被误伤——over-mask 是安全方向。
	if out := Redact("bypass=true"); !strings.Contains(out, "bypass=****") {
		t.Errorf("bypass 误伤是有意为之的安全方向代价: %q", out)
	}
	// auth 不得吞掉伪前缀词：author 不是凭证键。
	if out := Redact("author=Zhang San"); out != "author=Zhang San" {
		t.Errorf("author 被误伤: %q", out)
	}
}

// TestRedactKVJSONStructurePreserved 回归（guardx#44 文本路径）：JSON 行的
// 键值对打码后必须仍是合法 JSON——引号/冒号保形，行内其余部分不动。
// 此前 Repl 把分隔段吞成 `=`，采集侧 JSON 解析器整行降级。
func TestRedactKVJSONStructurePreserved(t *testing.T) {
	cases := []struct{ in, want string }{
		{`{"api_key": "sk-123"}`, `{"api_key": "****"}`},
		{`{"users":[{"api_key":"sk-1"},{"api_key":"sk-2"}]}`, `{"users":[{"api_key":"****"},{"api_key":"****"}]}`},
		{`{"a":1,"api_key":"sk-9","b":2}`, `{"a":1,"api_key":"****","b":2}`},
		{`{"key": "value"}`, `{"key": "****"}`},
		{`{"authorization": "Bearer xyz"}`, `{"authorization": "****"}`},
	}
	for _, c := range cases {
		out := Redact(c.in)
		if out != c.want {
			t.Errorf("Redact(%q) = %q, want %q", c.in, out, c.want)
		}
		if !json.Valid([]byte(out)) {
			t.Errorf("Redact(%q) 输出非法 JSON: %q", c.in, out)
		}
	}
	// 单引号 kv 内嵌在 JSON 字符串值里：引号形态各自回填，不向外交错注入。
	out := Redact(`{"note": "set password: 'x' ok"}`)
	if !json.Valid([]byte(out)) || strings.Contains(out, `"****"')`) {
		t.Errorf("内嵌单引号 kv 不应破坏外层 JSON: %q", out)
	}
}

// TestRedactKVJSONBearerAnchor 回归（bearer/jwt/vendor 提到 kv 规则之前）：
// `auth=Bearer <JWT>` 形态此前由 kv 规则吃掉 Bearer 锚点，JWT 漏网。
func TestRedactKVJSONBearerAnchor(t *testing.T) {
	out := Redact("auth=Bearer eyJhbGciOiJIUzI1NiJ9.e30.sig")
	if strings.Contains(out, "eyJhbGciOiJIUzI1NiJ9") {
		t.Errorf("auth=Bearer 形态 JWT 泄漏: %q", out)
	}
}
