package logredact

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// 本文件是集成方实弹反哺缺陷的回归钉子：guardx#50/#51/#52 一批（2026-11），
// guardx#57/#63/#64/#69/#75/#76/#77/#81 一批（2026-11）。
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

// ── guardx#57/#75：通用敏感形态收编——glpat-/AIza/长 hex ───────────────────

// TestRedactGitLabPATPrefix 回归（guardx#57）：平台前缀名单缺 glpat-（GitLab
// PAT，官方格式 glpat-[A-Za-z0-9_-]{20,}），v0.19.0 实测 clone URL 凭据/
// webhook secret 原样泄漏——issue 正文复现逐字入测。
func TestRedactGitLabPATPrefix(t *testing.T) {
	in := "clone https://gitlab.com/user/repo.git with glpat-AbCdEf1234567890-_xyz from keychain"
	out := Redact(in)
	if strings.Contains(out, "glpat-AbCdEf") {
		t.Fatalf("glpat- 泄漏: %q", out)
	}
	// 无凭据的 URL 部分不动（保结构是掩码承诺）
	if !strings.Contains(out, "https://gitlab.com/user/repo.git") {
		t.Fatalf("URL 结构应保留: %q", out)
	}
	// 带键形态（键在词表内）不依赖 vendor 规则
	if out := Redact(`{"gitlab_token":"glpat-AbCdEf1234567890-_xyz"}`); strings.Contains(out, "glpat-") {
		t.Fatalf("带键 glpat- 泄漏: %q", out)
	}
}

// TestRedactGoogleKeyAndLongHex 回归（guardx#75 收编清单）：Google API key
// （AIza+35 位）与长十六进制 ≥32（agent-memory 生产实证：32 位 hex API key
// 整值泄漏）此前均需消费仓自维护补丁规则。
func TestRedactGoogleKeyAndLongHex(t *testing.T) {
	out := Redact("google key AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q leaked")
	if strings.Contains(out, "AIza") {
		t.Fatalf("AIza key 泄漏: %q", out)
	}
	for _, in := range []string{
		"blob=deadbeefdeadbeefdeadbeefdeadbeef",            // 32 位 hex API key 形态
		"privkey=0123456789abcdef0123456789abcdef01234567", // 44 位（私钥材料形态）
	} {
		if out := Redact(in); strings.Contains(out, "deadbeef") || strings.Contains(strings.ToLower(out), "0123456789abcdef") {
			t.Fatalf("长 hex 泄漏: %q -> %q", in, out)
		}
	}
	// 短 hex（<32，如 IPv4 十六进制/短摘要）不误伤
	for _, plain := range []string{"hash=deadbeef", "csum=cafe1234"} {
		if out := Redact(plain); out != plain {
			t.Errorf("短 hex 不应误掩: %q -> %q", plain, out)
		}
	}
}

// TestRedactorUnionOrderContract 回归（guardx#75 文档化）：并集顺序
// 「先内置、后扩展」升格为契约——扩展规则见得到内置保留的结构锚点
// （scheme/用户名），见不到内置已打码的凭据本体。
func TestRedactorUnionOrderContract(t *testing.T) {
	red := NewRedactor([]Rule{{
		Name: "post-structure",
		Re:   regexp.MustCompile(`postgres://([^:\s]+):\*\*\*\*@`),
		Repl: "URL-MASKED",
	}})
	out := red("dsn=postgres://u:secretpw@h/db")
	// 内置先打码且保结构（scheme/用户名留着），扩展只能匹配到结构残形
	if !strings.Contains(out, "URL-MASKED") {
		t.Fatalf("扩展规则应锚定内置保留的结构形态: %q", out)
	}
	if strings.Contains(out, "secretpw") {
		t.Fatalf("凭据本体泄漏: %q", out)
	}
}

// ── guardx#64/#75/#77：URL userinfo——任意 scheme + 空用户名文法 ───────────

// TestRedactURLCredentialSchemeAndGrammar 回归（guardx#64 scheme 词表不全 /
// guardx#77 空用户名量词缺陷 / guardx#75 任意 scheme 收编）：
// 词表修到再全也救不了 `://:pass@` 的文法缺陷——scheme 改 RFC 3986 通用形状、
// 用户名段改可空，两个缺陷一次修。探针电池含 #77 全部 8 个 scheme 形态。
func TestRedactURLCredentialSchemeAndGrammar(t *testing.T) {
	cases := []struct{ name, in, cred string }{
		// guardx#77：scheme 全在旧表内、userinfo 文法缺陷（空用户名）
		{"redis 空用户名", "redis://:s3cretpass@host:6379/0", "s3cretpass"},
		{"postgres 空用户名", "postgres://:pw123@host/db", "pw123"},
		{"postgresql 空用户名", "postgresql://:password@host/db", "password"},
		{"mongodb 空用户名", "mongodb://:pw123@host/db", "pw123"},
		{"mysql 空用户名", "mysql://:pw123@host/db", "pw123"},
		{"https 空用户名", "https://:tok123@cdn.example.com/x", "tok123"},
		{"amqp 空用户名", "amqp://:guestpw@mq:5672", "guestpw"},
		{"rediss 空用户名", "rediss://:s3cret@cache:6380", "s3cret"},
		// guardx#64：驱动后缀/加密后缀（旧词表整体不命中）
		{"SQLAlchemy psycopg2", "dsn=postgresql+psycopg2://user:pw@db_host/db", ":pw@"},
		{"SQLAlchemy pymysql", "mysql+pymysql://root:secret@127.0.0.1/db", "secret"},
		{"TLS mqtts", "mqtts://dev:pass@broker:8883", "pass"},
		{"sftp", "sftp://user:pass@files.example.com/backup.tar", "pass"},
		// 存量承诺：常规形态不回退
		{"nats 常规", "nats://ops:s3cret@10.0.0.5:4222", "s3cret"},
		{"mongodb+srv", "mongodb+srv://user:passw0rd@cluster.example.net/", "passw0rd"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := Redact(c.in)
			if strings.Contains(out, c.cred) {
				t.Fatalf("泄漏: %q -> %q", c.in, out)
			}
		})
	}
	// 掩码保结构：scheme、用户名、主机留着（「认得出是哪条凭据」）
	if out := Redact("redis://app:s3cret@10.0.0.5:6379"); out != "redis://app:****@10.0.0.5:6379" {
		t.Fatalf("掩码应保结构: %q", out)
	}
	// 空用户名形态的掩码形状
	if out := Redact("redis://:s3cret@host"); out != "redis://:****@host" {
		t.Fatalf("空用户名掩码形状: %q", out)
	}
	// 纯用户名（无密码）不掩：ssh://git@github.com 是 git clone 日志最高频
	// URL，用户名不是凭据（#77 建议的取舍：token-作-用户名由 vendor 前缀兜）
	for _, plain := range []string{
		"git clone ssh://git@github.com/oagentkit/guardx.git",
		"postgres://postgres@localhost/db",
		"https://example.com/docs?a=b",
	} {
		if out := Redact(plain); out != plain {
			t.Errorf("纯用户名/无 userinfo URL 不应误掩: %q -> %q", plain, out)
		}
	}
}

// ── guardx#69：hintMatch 组捕获失败回退全量打码 ─────────────────────────────

// TestHintMatchFallbackFullMask 回归（guardx#69）：Group 越界/可选组未参与
// 匹配时回退整段 MaskHint——保留的尾 4 字符落在凭据上（Rule.Group 注释
// 自述的「线索=泄露」陷阱）。回退分支一律全量打码：宁可丢线索，不留尾巴。
// 键面用 app=（不在凭证词表内），隔离内置 kv 规则的干扰。
func TestHintMatchFallbackFullMask(t *testing.T) {
	// 组越界（Group=2 但正则只有 1 个捕获组）
	r := Rule{Name: "oob", Re: regexp.MustCompile(`app=(\w+)`), Style: MaskStyleHint, Keep: 4, Group: 2}
	if got := RedactWith("app=SUPERSECRETVALUE", []Rule{r}); got != "****" {
		t.Fatalf("越界组应整段全量打码，得到 %q", got)
	}
	// 可选组未参与匹配（x 前缀分支未走）
	r2 := Rule{Name: "opt", Re: regexp.MustCompile(`app=(?:x(\w+)|\w+)`), Style: MaskStyleHint, Keep: 4, Group: 1}
	if got := RedactWith("app=SUPERSECRETVALUE", []Rule{r2}); got != "****" {
		t.Fatalf("未参与组应整段全量打码，得到 %q", got)
	}
	// 正常 Group 仍保线索（不因回退收紧而丢档）
	r3 := Rule{Name: "ok", Re: regexp.MustCompile(`app=(\w+)`), Style: MaskStyleHint, Keep: 4, Group: 1}
	if got := RedactWith("app=SUPERSECRETVALUE1234", []Rule{r3}); got != "app=SUPE****1234" {
		t.Fatalf("捕获组掩码不应回退，得到 %q", got)
	}
	// Group=0（整段 hint）是文档化的另一档，不走回退分支
	r4 := Rule{Name: "whole", Re: regexp.MustCompile(`app=\w+`), Style: MaskStyleHint, Keep: 4}
	if got := RedactWith("app=SUPERSECRETVALUE1234", []Rule{r4}); got != "app=****1234" {
		t.Fatalf("整段 hint 档不应变，得到 %q", got)
	}
}

// ── guardx#63/#76：RedactValue 类型化容器 + map[string]string 盲区 ─────────

// TestRedactValueTypedMaps 回归（guardx#63/#76）：类型开关只认
// map[string]any/[]any，map[string]string（agent-harness pii 包注释在案的
// 已知结构盲区）等类型化容器 default 原样返回——静默漏脱。反射下探后：
// 键过键名判定、字符串值过文本规则、输出为副本。
func TestRedactValueTypedMaps(t *testing.T) {
	in := map[string]string{
		"password": "hunter2",
		"dsn":      "postgres://u:pw@h/db",
		"note":     "safe",
	}
	out, ok := RedactValue(in).(map[string]string)
	if !ok {
		t.Fatalf("map[string]string 应还回 map[string]string: %T", RedactValue(in))
	}
	if out["password"] != "****" {
		t.Fatalf("凭证词键应整值打码: %q", out["password"])
	}
	if strings.Contains(out["dsn"], "pw@") {
		t.Fatalf("字符串值应过文本规则: %q", out["dsn"])
	}
	if out["note"] != "safe" {
		t.Fatalf("无凭据值不应改动: %q", out["note"])
	}
	// 副本语义：入参不被污染
	if in["password"] != "hunter2" || in["dsn"] != "postgres://u:pw@h/db" {
		t.Fatalf("入参被污染: %v", in)
	}

	// 命名 string 元素类型：掩码经 Convert 还型（type Password string 字段
	// 掩码后仍是该类型），文本规则同样生效
	type secret string
	tin := map[string]secret{"password": "hunter2", "dsn": "postgres://u:pw@h/db"}
	tout, ok := RedactValue(tin).(map[string]secret)
	if !ok {
		t.Fatalf("map[string]secret 应还回同类型: %T", RedactValue(tin))
	}
	if tout["password"] != secret("****") {
		t.Fatalf("命名 string 键命中应整值打码还型: %q", tout["password"])
	}
	if strings.Contains(string(tout["dsn"]), "pw@") {
		t.Fatalf("命名 string 值应过文本规则: %q", tout["dsn"])
	}

	// 具体数字元素类型承载不了掩码字面量：只下探不整值掩（数字本体不是
	// 凭据文本，类型系统的硬边界——文档明示的行为）
	if got := RedactValue(map[string]int{"password": 42}).(map[string]int)["password"]; got != 42 {
		t.Fatalf("数字元素不应被改写: %v", got)
	}

	// 非字符串键只下探值
	iin := map[int]string{1: "token=abc"}
	if got := RedactValue(iin).(map[int]string)[1]; strings.Contains(got, "abc") {
		t.Fatalf("非字符串键的值应下探: %q", got)
	}
}

// TestRedactValueTypedSlicesAndStructs 回归（guardx#63）：[]string、
// []map[string]any、struct 导出字段（字段名过键名判定）、指针一律下探；
// 未导出字段反射不可读（原样，边界文档明示）。
func TestRedactValueTypedSlicesAndStructs(t *testing.T) {
	// []string
	sout := RedactValue([]string{"token=abc", "safe"}).([]string)
	if strings.Contains(sout[0], "abc") || sout[1] != "safe" {
		t.Fatalf("[]string 下探不符: %v", sout)
	}
	// []map[string]any（typed 容器嵌 any 容器）
	nin := []map[string]any{{"api_key": "sk-xyz"}, {"note": "ok"}}
	nout := RedactValue(nin).([]map[string]any)
	if nout[0]["api_key"] != "****" || nout[1]["note"] != "ok" {
		t.Fatalf("[]map[string]any 下探不符: %v", nout)
	}
	// struct：导出字段名过键名判定、字符串字段过文本规则、标量不动
	type conn struct {
		DSN        string
		Password   string
		AuthToken  string
		RetryCount int
	}
	got, ok := RedactValue(conn{
		DSN:        "redis://:pw@h/db",
		Password:   "hunter2",
		AuthToken:  "opaque-token-123",
		RetryCount: 3,
	}).(conn)
	if !ok {
		t.Fatalf("struct 应还回同类型: %T", RedactValue(conn{}))
	}
	if strings.Contains(got.DSN, ":pw@") {
		t.Fatalf("struct 字符串字段应过文本规则: %q", got.DSN)
	}
	if got.Password != "****" || got.AuthToken != "****" {
		t.Fatalf("凭证词字段名应整值打码: %q %q", got.Password, got.AuthToken)
	}
	if got.RetryCount != 3 {
		t.Fatalf("标量字段不应改动: %v", got.RetryCount)
	}
	// 指针下探还回指针
	pgot, ok := RedactValue(&conn{Password: "hunter2"}).(*conn)
	if !ok || pgot.Password != "****" {
		t.Fatalf("指针应下探还回指针: %v", pgot)
	}
	// 未导出字段反射不可读（原样）——此类类型请传导出形态
	type opaque struct{ secret string }
	ogot := RedactValue(opaque{secret: "hunter2"}).(opaque)
	if ogot.secret != "hunter2" {
		t.Fatalf("未导出字段应原样（反射边界）: %q", ogot.secret)
	}
	// json.Number 特赦：数字字面量保形（JSON 路径大整数精度承诺）
	big := json.Number("123456789012345678901234567890")
	if got := RedactValue(map[string]any{"big": big}).(map[string]any)["big"]; got != big {
		t.Fatalf("json.Number 应保形: %v", got)
	}
	// []byte 是二进制不是文本，原样
	raw := []byte{0xde, 0xad, 0xbe, 0xef}
	if got := RedactValue(raw).([]byte); !bytes.Equal(got, raw) {
		t.Fatalf("[]byte 应原样: %v", got)
	}
}

// TestRedactValueCycleBounded 类型化值的自引用环有深度上限（无上限会挂死
// 脱敏链路）——JSON 解码值不可能成环，本测只钉「不栈溢出、能返回」。
func TestRedactValueCycleBounded(t *testing.T) {
	cyclic := map[string]any{}
	cyclic["self"] = cyclic
	out := RedactValue(cyclic) // 有上限 ⇒ 必然返回
	if out == nil {
		t.Fatal("自引用环应受深度上限保护并返回")
	}
}

// TestRedactValueExtraRulesValuePatterns 回归（guardx#76 值模式检测缝）：
// 手机号/身份证这类值本身即敏感、无键名可依的形态，经 ExtraRules 注入
// 结构化路径的字符串叶子——agent-harness 整包自研 pii 的递归面由此收编，
// 只留值模式正则（地区口径刻意不进内置表）。
func TestRedactValueExtraRulesValuePatterns(t *testing.T) {
	opts := ValueOptions{ExtraRules: []Rule{
		{Name: "cn-mobile", Re: regexp.MustCompile(`\b1[3-9]\d{9}\b`), Repl: "****"},
		{Name: "cn-idcard", Re: regexp.MustCompile(`\b\d{17}[0-9Xx]\b`), Repl: "****"},
	}}
	in := map[string]any{
		"contact":  "手机 13812345678 失联",
		"ids":      []any{"身份证 11010119900307867X", "ok"},
		"typed":    map[string]string{"caller": "13812345678"},
		"password": "hunter2", // 内置键表承诺不因 ExtraRules 松动
		"keep":     "普通文本 12345",
	}
	out := RedactValueOpts(in, opts).(map[string]any)
	s, _ := out["contact"].(string)
	if strings.Contains(s, "13812345678") {
		t.Fatalf("手机号值模式漏掩: %q", s)
	}
	ids := out["ids"].([]any)
	if strings.Contains(ids[0].(string), "11010119900307867X") {
		t.Fatalf("身份证值模式漏掩: %q", ids[0])
	}
	if ids[1] != "ok" {
		t.Fatalf("普通值不应改动: %v", ids[1])
	}
	typed := out["typed"].(map[string]string)
	if strings.Contains(typed["caller"], "13812345678") {
		t.Fatalf("类型化容器字符串叶子应过 ExtraRules: %q", typed["caller"])
	}
	if out["password"] != "****" {
		t.Fatalf("内置键表承诺不应松动: %v", out["password"])
	}
	if out["keep"] != "普通文本 12345" {
		t.Fatalf("无命中值不应改动: %v", out["keep"])
	}
	// 零值 Options = 不带扩展（手机号值原样——值模式是调用方口径）
	plain := RedactValueOpts(map[string]any{"contact": "13812345678"}, ValueOptions{})
	if plain.(map[string]any)["contact"] != "13812345678" {
		t.Fatalf("零值 Options 不应套用扩展: %v", plain)
	}
}

// ── guardx#81：RFC 7235 方案词锚定——Basic 裸形态 ───────────────────────────

// TestRedactAuthSchemeWords 回归（guardx#81）：方案锚定只有 Bearer——
// Basic <base64>（一解码即明文 user:pass）在非词表键名（auth_header/
// proxy_auth）下整段泄漏。方案词表推广后存量 Bearer 形态不回退；Token
// 刻意不入表（LLM usage 散文计量行，#52 契约）。
func TestRedactAuthSchemeWords(t *testing.T) {
	cases := []struct{ name, in, cred string }{
		{"issue 复现 auth_header", "auth_header=Basic dXNlcjpwYXNzMTIz", "dXNlcjpwYXNzMTIz"},
		{"非词表键 proxy_auth", "proxy_auth=Negotiate YIIphzGCSqGSIb3Eg", "YIIphzGCSqGSIb3Eg"},
		{"散文 curl 头", "curl -H 'X-Auth: Basic c2VjcmV0dXNlcjpwYXNz'", "c2VjcmV0dXNlcjpwYXNz"},
		{"Digest 摘要", "auth_header=Digest username=alice response=deadbeefdeadbeefdeadbeefdeadbeef", "deadbeefdeadbeefdeadbeefdeadbeef"},
		{"存量 Bearer", "auth=Bearer gf7t2xK9randomOpaqueToken0a1b2c", "gf7t2xK9randomOpaqueToken0a1b2c"},
		{"存量 Authorization 头", "Authorization: Basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA=="},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if out := Redact(c.in); strings.Contains(out, c.cred) {
				t.Fatalf("泄漏: %q -> %q", c.in, out)
			}
		})
	}
	// 存量收敛形态不回退：kv 吞掉方案词前缀，输出单段掩码
	if out := Redact("auth=Bearer tok.en.sig"); out != "auth=****" {
		t.Fatalf("auth=Bearer 应收敛为单段掩码: %q", out)
	}
	// 方案词刻意不含 Token：LLM usage 散文计量行不误掩（#52 契约）
	for _, in := range []string{
		"request used prompt tokens 500, completion tokens 120",
		"total tokens 46 cached tokens 3",
	} {
		if out := Redact(in); out != in {
			t.Errorf("usage 计量散文被误掩: %q -> %q", in, out)
		}
	}
}
