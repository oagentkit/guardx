package logredact

import (
	"regexp"
	"strings"
	"sync"
	"testing"
)

// Rules() 必须给副本：调用方要能自由改自己的表，改到一半不能污染全进程的内置表。
func TestRulesReturnsCopy(t *testing.T) {
	rs := Rules()
	if len(rs) == 0 {
		t.Fatal("内置规则表不应为空")
	}
	before := len(rs)
	rs[0].Repl = "MUTATED"
	rs = append(rs, Rule{Name: "extra", Re: regexp.MustCompile(`x`), Repl: "y"})

	if len(Rules()) != before {
		t.Fatalf("Rules() 必须返回副本：追加后内置表长度从 %d 变成 %d", before, len(Rules()))
	}
	if out := Redact("password=secret"); strings.Contains(out, "MUTATED") {
		t.Fatalf("改副本污染了内置表：%q", out)
	}
	// 每条内置规则都该有名字（扩展规则出错时要能指出是哪一条）
	for _, r := range Rules() {
		if r.Name == "" {
			t.Fatal("内置规则缺 Name")
		}
		if r.Re == nil {
			t.Fatalf("内置规则 %q 缺 Re", r.Name)
		}
	}
}

// 应用顺序：**先内置、后扩展**。
// 扩展规则看到的是内置规则处理**之后**的文本。
func TestRedactWithOrder(t *testing.T) {
	// 内置规则把 "password=secret" 变成 "password=****"，
	// 扩展规则匹配 "****" → 说明它跑在内置之后。
	extra := []Rule{{Name: "after-builtin", Re: regexp.MustCompile(`\*\*\*\*`), Repl: "[MASKED]"}}
	got := RedactWith("password=secret", extra)
	if !strings.Contains(got, "[MASKED]") {
		t.Fatalf("扩展规则应在内置规则之后生效，得到 %q", got)
	}

	// 扩展规则之间按声明顺序生效
	two := []Rule{
		{Name: "first", Re: regexp.MustCompile(`custom`), Repl: "A"},
		{Name: "second", Re: regexp.MustCompile(`A`), Repl: "B"},
	}
	if got := RedactWith("custom=value", two); got != "B=value" {
		t.Fatalf("扩展规则声明顺序不对，得到 %q", got)
	}
}

// 内置规则先跑，扩展规则就拿不到原始凭据——这正是「先内置」的意义。
func TestRedactWithBuiltInWins(t *testing.T) {
	extra := []Rule{{Name: "eats-raw", Re: regexp.MustCompile(`secret`), Repl: "LEAKED"}}
	got := RedactWith("password=secret", extra)
	if strings.Contains(got, "LEAKED") {
		t.Fatalf("内置规则应先于扩展规则生效，得到 %q", got)
	}
}

// 扩展规则与内置规则是**互补**关系：内置没覆盖的形态由扩展兜住。
func TestRedactWithExtendsCoverage(t *testing.T) {
	const blob = "blob=deadbeefdeadbeefdeadbeefdeadbeef"
	// 内置表没有「长十六进制」这一档 → 原文不动
	if out := Redact(blob); out != blob {
		t.Fatalf("内置表不应命中长 hex，得到 %q", out)
	}
	extra := []Rule{{
		Name: "long-hex",
		Re:   regexp.MustCompile(`(?i)\b[0-9a-f]{32,}\b`),
		Repl: "****",
	}}
	out := RedactWith(blob, extra)
	if strings.Contains(out, "deadbeef") {
		t.Fatalf("扩展规则未生效，得到 %q", out)
	}
}

// NewRedactor 快照规则表：构造之后调用方改自己的切片，不影响已构造的脱敏器。
func TestNewRedactorSnapshotsRules(t *testing.T) {
	extra := []Rule{{Name: "x", Re: regexp.MustCompile(`foo`), Repl: "BAR"}}
	red := NewRedactor(extra)
	if got := red("foo"); got != "BAR" {
		t.Fatalf("脱敏器未生效，得到 %q", got)
	}
	extra[0].Repl = "MUTATED"
	if got := red("foo"); got != "BAR" {
		t.Fatalf("构造后修改调用方切片不应影响脱敏器，得到 %q", got)
	}
}

// 扩展规则里 Re 为 nil 不能让整条链路崩（扩展表是调用方给的）。
func TestRedactWithNilRegexSkipped(t *testing.T) {
	extra := []Rule{{Name: "broken", Re: nil, Repl: "x"}}
	if got := RedactWith("password=secret", extra); !strings.Contains(got, "****") {
		t.Fatalf("nil 规则应被跳过，得到 %q", got)
	}
}

// 脱敏器并发安全（只读规则表，不改共享状态）。
func TestNewRedactorConcurrent(t *testing.T) {
	red := NewRedactor([]Rule{{Name: "x", Re: regexp.MustCompile(`foo`), Repl: "BAR"}})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if got := red("password=secret foo"); !strings.Contains(got, "BAR") {
					t.Errorf("并发下结果不对：%q", got)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// 保定位线索的不可逆掩码
// ---------------------------------------------------------------------------

func TestMaskHint(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"空串", "", ""},
		// 太短 → 全量打码（留 8 个字符只藏 1 个，等于没藏）
		{"太短全量打码", "short", "****"},
		// 够长 → 保留首尾各 4
		{"保留首尾", "sk-ant-api03-abcdefghijklmnopqrst", "sk-a****qrst"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := MaskHint(c.in); got != c.want {
				t.Fatalf("MaskHint(%q) = %q，期望 %q", c.in, got, c.want)
			}
		})
	}
}

// 保留位**封顶**、输出长度**固定**：不随原值长度变化。
func TestMaskHintLengthIsFixed(t *testing.T) {
	short := MaskHint("abcdefghijklmnop")
	long := MaskHint("abcdefghijklmnopqrstuvwxyz0123456789")
	if len(short) != len(long) {
		t.Fatalf("输出长度不应随原值变化：%d vs %d", len(short), len(long))
	}
	if !strings.HasPrefix(long, "abcd") || !strings.HasSuffix(long, "6789") {
		t.Fatalf("应保留首尾各 4，得到 %q", long)
	}
	// 保留位封顶：无论原值多长，只留 4+4
	if strings.Count(long, "a") > 1 {
		t.Fatalf("保留字符数不应超过 keep，得到 %q", long)
	}
}

// 不可复原：原值的中段不出现在掩码里。
func TestMaskHintNotReversible(t *testing.T) {
	orig := "supersecretvalue0123456789"
	masked := MaskHint(orig)
	if masked == orig {
		t.Fatal("掩码后不能等于原值")
	}
	if strings.Contains(masked, "secretvalue") {
		t.Fatalf("中段泄漏：%q", masked)
	}
}

// 保留位数可配；非法值回退默认。
func TestMaskHintWith(t *testing.T) {
	if got := MaskHintWith("abcdefgh", 2); got != "ab****gh" {
		t.Fatalf("keep=2 得到 %q", got)
	}
	if got := MaskHintWith("abcdefgh", 0); got != MaskHint("abcdefgh") {
		t.Fatalf("keep<=0 应回退默认，得到 %q", got)
	}
}

// 规则级：MaskStyleHint 档 + 捕获组定位。
func TestRuleHintStyle(t *testing.T) {
	// 用 Group 圈出凭据本体：保留额度花在凭据上，而不是被上下文吃掉。
	r := Rule{
		Name:  "app-secret",
		Re:    regexp.MustCompile(`app=(\S+)`),
		Style: MaskStyleHint,
		Keep:  4,
		Group: 1,
	}
	got := RedactWith("app=SUPERSECRETVALUE1234", []Rule{r})
	if got != "app=SUPE****1234" {
		t.Fatalf("捕获组掩码得到 %q", got)
	}
	// 整段掩码（Group=0）时，保留的头 4 个字符落在上下文里
	r2 := r
	r2.Group = 0
	got2 := RedactWith("app=SUPERSECRETVALUE1234", []Rule{r2})
	if got2 != "app=****1234" {
		t.Fatalf("整段掩码得到 %q", got2)
	}
}

// 两档掩码是**不同档**：全量打码认不出是哪一条，线索档认得出但还原不了。
func TestMaskTiersAreDifferent(t *testing.T) {
	secret := "sk-ant-api03-abcdefghijklmnopqrst"
	full := Redact(secret)
	hint := MaskHint(secret)
	if full == hint {
		t.Fatalf("两档不应相同：%q", full)
	}
	if strings.Contains(full, "sk-a") {
		t.Fatalf("全量打码不该保留线索：%q", full)
	}
	if !strings.Contains(hint, "sk-a") {
		t.Fatalf("线索档应保留首部：%q", hint)
	}
}
