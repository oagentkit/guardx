package logredact

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// 本文件是 guardx#50/#51/#52 三缺陷的回归钉子（2026-11 集成方实弹反哺）：
// 每组先钉「修后的正确形态」，再钉「相邻词表的存量承诺不回退」。

// ── guardx#52：tokens 复数收窄——LLM usage 计量字段不再整值打码 ──────────────

// TestRedactUsageMetricTokensSurvive usage 计量字段（prompt_tokens 族 +
// camelCase 变体）是结构化日志高频合法键，v0.18.0 的 tokens? 后缀把它们
// 整值打成 "****"（计价/评测/配额读到掩码 = 账本方向静默错）。
func TestRedactUsageMetricTokensSurvive(t *testing.T) {
	usage := `{"usage":{"prompt_tokens":12,"completion_tokens":34,"total_tokens":46,"cached_tokens":3,"reasoning_tokens":5}}`
	out := string(RedactJSON([]byte(usage)))
	for _, want := range []string{
		`"prompt_tokens":12`, `"completion_tokens":34`, `"total_tokens":46`,
		`"cached_tokens":3`, `"reasoning_tokens":5`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("usage 计量字段被误掩: %s 缺 %s", out, want)
		}
	}
	if !json.Valid([]byte(out)) {
		t.Errorf("输出非法 JSON: %s", out)
	}
	// 文本路径同样存活（此前 `prompt_tokens: 12` 被打码）
	for _, in := range []string{
		`prompt_tokens: 12`, `total_tokens=46`, `promptTokens: 12`, `max_tokens: 4096`,
	} {
		if out := Redact(in); out != in {
			t.Errorf("计量字段文本形态被误掩: %q -> %q", in, out)
		}
	}
}

// TestRedactCredentialTokenFormsStillMasked 收窄只动复数计量形态，凭证
// token 形态的存量承诺一件不回退。裸复数 tokens（令牌池形态）在 JSON 面
// 保持命中（^tokens$ 整键判定）；文本面裸复数不命中——RE2 无环视，裸
// tokens 与 scout_tokens 这类计量复合词在文本面无法区分（已知不对称，
// 结构化载荷走 JSON 面即覆盖）。
func TestRedactCredentialTokenFormsStillMasked(t *testing.T) {
	for _, in := range []string{
		`{"token":"tk_1"}`, `{"access_token":"at_1"}`, `{"refresh_token":"rt_1"}`,
		`{"api_token":"pt_1"}`, `{"auth_token":"aut_1"}`, `{"session_token":"st_1"}`,
		`{"x-api-token":"xt_1"}`, `{"my_access_token":"mt_1"}`, `{"github_token":"gh_1"}`,
		`{"apiToken":"ap_1"}`, `{"accessToken":"ac_1"}`,
		"token: tk_bare", `access_token=tk_dq`,
	} {
		if out := Redact(in); strings.Contains(out, "tk_") || strings.Contains(out, "gh_1") ||
			strings.Contains(out, "ap_1") || strings.Contains(out, "ac_1") {
			t.Errorf("凭证 token 形态漏掩: %q -> %q", in, out)
		}
		if out := string(RedactJSON([]byte(in))); strings.Contains(out, "tk_") {
			t.Errorf("凭证 token 结构化形态漏掩: %q -> %q", in, out)
		}
	}
	// 裸复数 tokens（令牌池）：JSON 面整键命中；文本面不命中（无环视，
	// 见函数注释——已知不对称）
	if out := string(RedactJSON([]byte(`{"tokens":["tk_a","tk_b"]}`))); strings.Contains(out, "tk_") {
		t.Errorf("裸复数 tokens JSON 面漏掩: %q", out)
	}
}

// ── guardx#50：掩值保引号形状 + 截断/转义引号泄漏 ──────────────────────────

// TestRedactMaskedValueKeepsQuoteShape 掩值必须保留值原本的引号：脱敏常常
// 不是最后一棒，下游模式（审计关键词提取、二次解析）对着掩码后的文本写，
// 「值以引号收尾」的模式在掩码后必须仍能命中。
func TestRedactMaskedValueKeepsQuoteShape(t *testing.T) {
	out := Redact(`{"password":"s3cr3t","msg":"done"}`)
	if out != `{"password":"****","msg":"done"}` {
		t.Fatalf("掩码应保形: %q", out)
	}
	// 下游「值以引号收尾」模式在掩码后仍可命中（#50 的核心诉求）
	if !regexp.MustCompile(`"password":"[^"]*"`).MatchString(out) {
		t.Errorf("下游引号锚定模式失配: %q", out)
	}
	for _, in := range []string{`password: "secret"`, `password: 'secret'`, `password="secret"`} {
		if out := Redact(in); !strings.HasSuffix(out, `"****"`) && !strings.HasSuffix(out, `'****'`) {
			t.Errorf("掩码应保留收尾引号: %q -> %q", in, out)
		}
	}
}

// TestRedactTruncatedQuotedValueMasked 截断兜底：日志截断落在开引号之后
// （无收尾引号）时，v0.18.0 的闭引号值规则全部失配 ⇒ 整值原文泄漏。掩码
// 保留开引号（掩值不改引号的有无）。
func TestRedactTruncatedQuotedValueMasked(t *testing.T) {
	for _, in := range []string{`password: "abc`, `password: 'abc`, `{"password":"abc`, `token='abc`} {
		out := Redact(in)
		if strings.Contains(out, "abc") {
			t.Errorf("截断引号值泄漏: %q -> %q", in, out)
		}
		if !strings.Contains(out, `"****`) && !strings.Contains(out, `'****`) {
			t.Errorf("截断掩码应保留开引号: %q -> %q", in, out)
		}
	}
	// 闭引号形态存在时截断规则不抢（精确规则在前）
	if out := Redact(`password: "abc" tail`); out != `password: "****" tail` {
		t.Errorf("闭引号形态应走精确规则: %q", out)
	}
}

// TestRedactEscapedQuoteValueWholeMasked 转义引号值：v0.18.0 的 `"[^"\n]*"`
// 在 `"a\"b"` 处只掩到内嵌引号、留下 `b"}` 半截残形。转义感知后整值掩码。
func TestRedactEscapedQuoteValueWholeMasked(t *testing.T) {
	out := Redact(`{"password": "a\"b"}`)
	if strings.Contains(out, `b"}`) || !strings.Contains(out, `"****"`) {
		t.Fatalf("转义引号值应整值掩码: %q", out)
	}
	if !json.Valid([]byte(out)) {
		t.Errorf("输出非法 JSON: %q", out)
	}
}

// ── guardx#51：多段复合键、整值掩、键名判定回调 ────────────────────────────

// TestRedactCompoundCredentialKeys 多段复合键名（领属前缀 / kebab / 多段语义
// 前缀）两条路径都必须命中——jumpserver-kit 曾为这些形态自写词表兜底。
func TestRedactCompoundCredentialKeys(t *testing.T) {
	for _, in := range []string{
		`{"my_access_token":"v"}`, `{"x-api-key":"v"}`, `{"oauth_access_token":"v"}`,
		`{"our_password":"v"}`, `{"x_api_key":"v"}`,
	} {
		if out := string(RedactJSON([]byte(in))); strings.Contains(out, `"v"`) {
			t.Errorf("复合凭证键漏掩: %q -> %q", in, out)
		}
		if out := Redact(in); strings.Contains(out, ":v") || strings.Contains(out, "=v") {
			t.Errorf("复合凭证键文本路径漏掩: %q -> %q", in, out)
		}
	}
}

// TestRedactBracketValueWholeMasked 整值掩：凭证值是 JSON 数组/对象时，裸值
// 规则只会啃出 `****"a","b"]` 半截对象；括号形态（含截断）整值换掉。
func TestRedactBracketValueWholeMasked(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{`password=["a","b"]`, `password=****`},
		{`token={"k":"v"}`, `token=****`},
		{`password=["a","b"] tail`, `password=**** tail`},
		{`password=["a,"b`, `password=****`},
	} {
		if out := Redact(c.in); out != c.want {
			t.Errorf("Redact(%q) = %q, want %q", c.in, out, c.want)
		}
	}
}

// TestIsCredentialKeyPredicate 内置键名谓词 + 回调叠加：集成方喂自己的
// isCredentialKey（#51①），内置词表承诺不因回调松动（回调只加不减）。
func TestIsCredentialKeyPredicate(t *testing.T) {
	yes := []string{"password", "api_key", "x-api-key", "access_token", "apiKey", "client_secret", "tokens"}
	for _, k := range yes {
		if !IsCredentialKey(k) {
			t.Errorf("IsCredentialKey(%q) = false, want true", k)
		}
	}
	no := []string{"sort_key", "cache_key", "prompt_tokens", "total_tokens", "author", "keywords"}
	for _, k := range no {
		if IsCredentialKey(k) {
			t.Errorf("IsCredentialKey(%q) = true, want false", k)
		}
	}

	v := map[string]any{"custom_secret_field": "v", "keep": "1"}
	out := RedactValueOpts(v, ValueOptions{IsCredentialKey: func(k string) bool { return k == "custom_secret_field" }})
	m := out.(map[string]any)
	if m["custom_secret_field"] != maskLiteral || m["keep"] != "1" {
		t.Fatalf("回调键应整值打码、其余原样: %v", m)
	}

	out = RedactJSONOpts([]byte(`{"custom_secret_field":"v","prompt_tokens":12}`),
		ValueOptions{IsCredentialKey: func(k string) bool { return strings.HasSuffix(k, "_field") }})
	if !strings.Contains(string(out.([]byte)), `"custom_secret_field":"****"`) ||
		!strings.Contains(string(out.([]byte)), `"prompt_tokens":12`) {
		t.Fatalf("RedactJSONOpts 回调判定不符: %s", out)
	}

	// 零值 Options = 内置词表语义（等价 RedactValue/RedactJSON）
	if got := RedactValueOpts(map[string]any{"api_key": "v"}, ValueOptions{}); got.(map[string]any)["api_key"] != maskLiteral {
		t.Fatalf("零值 Options 应走内置词表: %v", got)
	}
}
