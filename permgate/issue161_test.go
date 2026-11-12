package permgate

// 2026-11-12 issue 清零战回归测试（#161）：钉住重定向段的 allow 失配。
// splitCommand 不拆重定向、hasCommandSubstitution 不认重定向——`git status > /etc/passwd`
// 曾搭 `git status:*` 的车原样放行，与「拆不动的形态宁可失配」的包注释承诺相反
// （#144 同根因新面）。与 #144 修复的口径差异必须钉住：双引号内的 `>` 是字面，
// 不得照抄替换体守门的双引号处理（会误伤 `git status "a>b"`）。

import "testing"

// TestHasRedirectForms_Issue161 hasRedirect 单元口径：引号内与转义为字面，
// 未引用化的 `>` `<`（含 `>>` `2>` `2>&1`）命中。
func TestHasRedirectForms_Issue161(t *testing.T) {
	cases := []struct {
		seg  string
		want bool
	}{
		{"git status > /etc/passwd", true},                      // 输出重定向
		{"git status >> /tmp/x", true},                          // 追加重定向
		{"git status 2>/dev/null", true},                        // fd 重定向
		{"git status 2>&1", true},                               // fd 复制
		{"git status < /etc/passwd", true},                      // 输入重定向
		{"git status>/etc/passwd", true},                        // 无空白也是重定向
		{"git log --format=%H > ~/.git/hooks/pre-commit", true}, // 可持久化写面
		{`git status "a>b"`, false},                             // 双引号内是字面（#144 口径不同处）
		{`git status 'a>b'`, false},                             // 单引号内是字面
		{`git status \>x`, false},                               // 反斜杠转义为字面
		{"git status --short", false},                           // 普通形态
		{"git status", false},                                   // 无操作符
	}
	for _, c := range cases {
		if got := hasRedirect(c.seg); got != c.want {
			t.Errorf("hasRedirect(%q) = %v, want %v", c.seg, got, c.want)
		}
	}
}

// TestAllowFailsOnRedirect_Issue161 端到端：allow 前缀规则对重定向形态恒失配
// （落 ask），deny 侧既有保守语义不受影响。
func TestAllowFailsOnRedirect_Issue161(t *testing.T) {
	// allow 侧：重定向不得搭前缀车。
	for _, cmd := range []string{
		"git status > /etc/passwd",
		"git status >> ~/.ssh/authorized_keys",
		"git status 2>/dev/null",
		"git status < /etc/passwd",
		"git status >/etc/passwd", // 无空白：prefixBoundary 本就不成立，双保险
	} {
		if matchRuleContent("git status:*", []subjectFace{{cmd}}, Allow) {
			t.Fatalf("allow 前缀不得放行重定向形态（guardx#161）: %q", cmd)
		}
	}
	// 不得误伤：正常前缀命中。
	if !matchRuleContent("git status:*", []subjectFace{{"git status --short"}}, Allow) {
		t.Fatal("普通前缀命中不得受 #161 修复影响")
	}
	// 不得误伤：引号内的 `>` 不是重定向（真实 shell 语义）。
	if !matchRuleContent("git status:*", []subjectFace{{`git status "a>b"`}}, Allow) {
		t.Fatal(`引号内 > 不是重定向，"a>b" 形态不得误伤`)
	}
	// deny 侧保守语义保持：重定向不削弱 deny 前缀命中。
	if !matchRuleContent("rm:*", []subjectFace{{"rm -rf / > /tmp/x"}}, Deny) {
		t.Fatal("deny 侧前缀命中语义不应被 #161 修复改变")
	}
}

// TestRedirectNoAllowRide_Issue161 端到端（Service 面，与 #129 同款）：
// allow 规则 `git status:*` 下带重定向的命令落 ask，正常命令仍放行。
func TestRedirectNoAllowRide_Issue161(t *testing.T) {
	s := &Service{
		ProjectRules: Ruleset{Allow: []Rule{{ToolName: "bash", Content: "git status:*"}}},
	}
	for _, cmd := range []string{
		"git status > /etc/passwd",
		"git status >> /tmp/x",
		"git status 2>/dev/null",
		"git status < /etc/passwd",
	} {
		if d := s.Check(ctx, "bash", cmd, ModeDefault, Capability{}); d.Behavior != Ask {
			t.Fatalf("重定向不得搭 allow 车（guardx#161）: %q => %+v", cmd, d)
		}
	}
	// 对照：正常前缀与引号内形态放行。
	for _, cmd := range []string{
		"git status --short",
		`git status "a>b"`,
	} {
		if d := s.Check(ctx, "bash", cmd, ModeDefault, Capability{}); d.Behavior != Allow {
			t.Fatalf("对照组应放行: %q => %+v", cmd, d)
		}
	}
	// deny 侧：重定向形态仍按前缀命中（yolo 压不过禁）。
	ds := &Service{
		ProjectRules: Ruleset{Deny: []Rule{{ToolName: "bash", Content: "rm:*"}}},
	}
	if d := ds.Check(ctx, "bash", "rm -rf / > /tmp/x", ModeYolo, Capability{}); d.Behavior != Deny {
		t.Fatalf("deny 不得被重定向削弱: %+v", d)
	}
}
