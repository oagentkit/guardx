package logredact

// 2026-11-14 issue 清零战回归（guardx#177-#180）：每单给「修复前泄漏样本 →
// 修复后中和」对照钉，防回归。

import (
	"strings"
	"testing"
)

// TestIssue177MultiWordBareValue guardx#177：凭证键的未引号值含空白此前只掩
// 首词（bareValue 窄形态在空白处收口）——`password=correct horse battery
// staple` 泄漏后 3 词。修复后凭证 kv 的未引号值吃满行尾；对照：通用 key-value
// 规则保持窄形态（散文不整行吞）、引号形态不受影响、JSON 行结构保住。
func TestIssue177MultiWordBareValue(t *testing.T) {
	// 修复前泄漏样本（bareValue 只吃 [^\s&'"]+）：`password=**** horse battery staple`
	for _, in := range []string{
		"password=correct horse battery staple",
		"password: hello world next",
		"passphrase: horse battery staple", // 词表已收 passphrases?
		"auth=Bearer some long token here",
	} {
		out := Redact(in)
		if strings.Contains(out, "horse battery staple") ||
			strings.Contains(out, "hello world next") ||
			strings.Contains(out, "some long token here") {
			t.Fatalf("多词裸值泄漏: %q -> %q", in, out)
		}
		if !strings.HasSuffix(out, "****") {
			t.Fatalf("未引号值应整值掩到行尾: %q -> %q", in, out)
		}
	}
	// 幂等：掩码形态二次过规则不变。
	if out := Redact(Redact("password=correct horse battery staple")); out != "password=****" {
		t.Fatalf("二次脱敏应幂等: %q", out)
	}
	// 对照 1：引号形态已由专用规则整值掩，行尾变体不得跨过引号吞掉 JSON 行
	// 后续字段（#44：打码动作本身不得破坏行结构）。
	in := `{"password": "abc", "user": "bob"}`
	if out := Redact(in); out != `{"password": "****", "user": "bob"}` {
		t.Fatalf("JSON 行结构应保住: %q -> %q", in, out)
	}
	// 对照 2：非凭证词的裸值键保持窄形态（多词值不被整行吞）。
	in = "note=hello world"
	if out := Redact(in); out != in {
		t.Fatalf("非凭证键不得误掩: %q -> %q", in, out)
	}
}

// TestIssue178KeysSuffix guardx#178：词表没有裸 keys?——`keys=`、`foo_key=`、
// `mykey=` 整值原文返回，与 #45 注释「key 的复数形态必须命中」直接打架。
// 修复后文本面与 JSON 面词表同步收编 keys?。
func TestIssue178KeysSuffix(t *testing.T) {
	// 修复前泄漏样本：三形态全部原样返回。
	for _, in := range []string{
		"keys=secretvalue123",
		"foo_key=secretvalue123",
		"mykey=secretvalue123",
		"session_keys=secretvalue123",
		`{"keys": "secretvalue123"}`,
		`{"foo_key": "secretvalue123"}`,
		`{"sort_key": "secretvalue123"}`,
	} {
		out := Redact(in)
		if strings.Contains(out, "secretvalue123") {
			t.Fatalf("keys 形态泄漏: %q -> %q", in, out)
		}
		if !strings.Contains(out, "****") {
			t.Fatalf("keys 形态应整值掩: %q -> %q", in, out)
		}
	}
	// JSON 面结构化路径同步（RedactValue 键感知）。
	out := RedactValue(map[string]any{"keys": "sv1", "foo_key": "sv2", "authorized_keys": "sv3"})
	m := out.(map[string]any)
	for k, v := range m {
		if v != "****" {
			t.Fatalf("JSON 面 keys 形态应整值掩: %s=%v", k, v)
		}
	}
	// 对照：keywords/keynote（key 后直连字母）不在词表，不误伤。
	if IsCredentialKey("keywords") {
		t.Fatal("keywords 不应命中（key 后直连字母，非 [-_] 分隔段）")
	}
	// 已知代价（词表注释）：以 keys 结尾的普通词误伤——over-mask 是安全方向。
	if out := Redact("monkeys=5"); !strings.Contains(out, "monkeys=****") {
		t.Fatalf("monkeys 误伤是有意为之的安全方向代价: %q", out)
	}
}

// TestIssue179URLPasswordSlash guardx#179：URL 内嵌凭据规则的密码段字符类
// [^\s@/]+ 在 `/` 处收口——密码含 `/` 的 userinfo 整体失配、原文落盘
// （guardx#77 同族文法缺陷）。修复后密码段 [^\s@]+，userinfo 终止于 @。
func TestIssue179URLPasswordSlash(t *testing.T) {
	// 修复前泄漏样本：密码含 / 的连接串整串原样返回。
	for _, in := range []string{
		"postgres://user:p/ass@host:5432/db",
		"redis://u:pa/ss@cache:6380",
		"https://token:abc/def@api.example.com/v1",
		"mysql://root:pa%2Fss@127.0.0.1/db", // 路径式密钥形态
	} {
		out := Redact(in)
		if strings.Contains(out, "p/ass") || strings.Contains(out, "pa/ss") ||
			strings.Contains(out, "abc/def") || strings.Contains(out, "pa%2Fss") {
			t.Fatalf("密码含 / 的 userinfo 泄漏: %q -> %q", in, out)
		}
	}
	// 掩码保结构：scheme、用户名、host、path 原样。
	if out := Redact("postgres://user:p/ass@host:5432/db"); out != "postgres://user:****@host:5432/db" {
		t.Fatalf("掩码应保结构: %q", out)
	}
	// 对照：path 内嵌 `:` 的形态不误吞——用户名段跨不过 `/`，规则整体不命中。
	for _, plain := range []string{
		"http://example.com/a:b@c",
		"https://example.com/docs?a=b",
		"git clone ssh://git@github.com/oagentkit/guardx.git",
	} {
		if out := Redact(plain); out != plain {
			t.Fatalf("path 内嵌冒号形态不应误掩: %q -> %q", plain, out)
		}
	}
}

// TestIssue180AuthorizationSeparatorShape guardx#180：authorization 裸值规则的
// Repl 硬编码 `=`，把原文的 `:` 改写掉——打码动作本身破坏行结构（#44 在裸面
// 的同款失效形态）。修复后捕获分隔段原样回填。
func TestIssue180AuthorizationSeparatorShape(t *testing.T) {
	// 修复前泄漏形态（非泄漏而是结构破坏）：`Authorization: Bearer x.y.z`
	// 打码后变成 `Authorization=****`（冒号变等号）。
	for _, c := range []struct{ in, want string }{
		{"Authorization: Bearer abc.def.ghi", "Authorization: ****"},
		{"authorization: Basic dXNlcjpwYXNz", "authorization: ****"},
		{"WWW-Authenticate: Basic realm=\"x\"", "WWW-Authenticate: ****"},
		{"www-authenticate = Bearer xyz", "www-authenticate = ****"},
		{"Authorization: Bearer abc\r\nX-Trace: t1", "Authorization: ****\r\nX-Trace: t1"},
	} {
		out := Redact(c.in)
		if out != c.want {
			t.Fatalf("分隔符应保形: %q -> %q, want %q", c.in, out, c.want)
		}
		if strings.Contains(out, "abc.def.ghi") || strings.Contains(out, "dXNlcjpwYXNz") ||
			strings.Contains(out, "Bearer xyz") {
			t.Fatalf("凭据体泄漏: %q -> %q", c.in, out)
		}
	}
	// 幂等：掩码形态二次过规则不变。
	if out := Redact("Authorization: ****"); out != "Authorization: ****" {
		t.Fatalf("二次脱敏应幂等: %q", out)
	}
	// 对照：JSON 引号形态保形不受影响（既有 #44 承诺）。
	if out := Redact(`{"authorization": "Bearer xyz"}`); out != `{"authorization": "****"}` {
		t.Fatalf("JSON 引号形态应保形: %q", out)
	}
}
