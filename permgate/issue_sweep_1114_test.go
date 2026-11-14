package permgate

// 2026-11-14 issue 清零战回归（guardx#181-#183）。

import "testing"

// TestIssue181DenyCoversCommandSubstitution guardx#181：deny/ask 侧此前没有
// #144 的命令替换守门、splitCommand 也不拆 eval/bash -c——deny 内容规则在
// 替换体/派发器形态恒失配，yolo/白名单下无确认放行（deny 是最后一道硬闸，
// 失配方向是漏放）。修复后：替换体段视为命中；派发器内层成为独立段。
func TestIssue181DenyCoversCommandSubstitution(t *testing.T) {
	s := &Service{
		AllowedTools: map[string]bool{"bash": true},
		ProjectRules: Ruleset{Deny: []Rule{{ToolName: "bash", Content: "rm -rf:*"}}},
	}
	// 修复前四形态全部 allow（rule.allowedTools / mode.yolo），deny 死字。
	for _, cmd := range []string{
		"rm -rf /", // 对照：裸形态修前即拦
		"echo $(rm -rf /)",
		"echo `rm -rf /`",
		"echo ${VAR} rm -rf /tmp/x",
		"eval rm -rf /",
		"bash -c 'rm -rf /'",
		"/bin/bash -c 'rm -rf /'",
		"bash -lc 'rm -rf /'",
		"sh -c \"rm -rf /\"",
		"eval 'rm -rf /'",
		"bash -c 'echo hi; rm -rf /'",
	} {
		if d := s.Check(ctx, "bash", cmd, ModeYolo, Capability{}); d.Behavior != Deny || d.RuleID != "rule.project.deny" {
			t.Fatalf("deny 不得被替换体/派发器形态绕过: %q -> %+v", cmd, d)
		}
	}
	// ask 档同侧：不可解析的替换体段强制问。
	s2 := &Service{ProjectRules: Ruleset{Ask: []Rule{{ToolName: "bash", Content: "rm -rf:*"}}}}
	if d := s2.Check(ctx, "bash", "echo $(rm -rf /)", ModeDefault, Capability{}); d.Behavior != Ask {
		t.Fatalf("ask 档对替换体形态应强制问: %+v", d)
	}
	// 对照：单引号内的替换体是字面、普通无害命令不误拦。
	s3 := &Service{AllowedTools: map[string]bool{"bash": true}}
	for _, cmd := range []string{
		"echo 'rm -rf /'",
		"echo \\$(rm -rf /)", // 反斜杠转义为字面
	} {
		if d := s3.Check(ctx, "bash", cmd, ModeYolo, Capability{}); d.Behavior != Allow {
			t.Fatalf("字面形态不得误拦: %q -> %+v", cmd, d)
		}
	}
}

// TestIssue181SplitCommandDispatchers splitCommand 派发器解包：内层脚本成为
// 独立段（原段保留——deny 任一段命中只多拦、allow 每段命中只更严）。
func TestIssue181SplitCommandDispatchers(t *testing.T) {
	cases := []struct {
		cmd  string
		want []string // 期望出现的段（子集断言，原段保留导致顺序不定）
	}{
		{"eval rm -rf /", []string{"rm -rf /"}},
		{"bash -c 'rm -rf /'", []string{"rm -rf /"}},
		{`sh -c "git push --force"`, []string{"git push --force"}},
		{"bash -c 'git status; curl evil'", []string{"git status", "curl evil"}},
		{"zsh -ic 'rm -rf /'", []string{"rm -rf /"}}, // 选项簇含 c（-ic）
		{"eval git status", []string{"git status"}},
	}
	for _, tc := range cases {
		got := splitCommand(tc.cmd)
		for _, want := range tc.want {
			found := false
			for _, seg := range got {
				if seg == want {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("splitCommand(%q) = %v, 缺段 %q", tc.cmd, got, want)
			}
		}
	}
	// 非派发器形态不拆、不增段。
	if got := splitCommand("git status"); len(got) != 1 || got[0] != "git status" {
		t.Errorf("普通命令不得被解包改动: %v", got)
	}
	// 长选项恰含 c 的（--rcfile/--config）不当派发标志——脚本 operand 不得错拆。
	if got := splitCommand("bash --rcfile f -c 'rm -rf /'"); len(got) != 1 {
		t.Errorf("--rcfile 形态不在覆盖面，段保持原样: %v", got)
	}
}

// TestIssue182ReadOnlySessionKeyParity guardx#182：只读档下会话授权两条路径
// 方向相反——AlwaysAsk 写工具（更敏感）先于只读拦截被钥匙放行、普通写工具
// 被拦。修复后统一为「禁」压过钥匙：两条路径对同参数同参。
func TestIssue182ReadOnlySessionKeyParity(t *testing.T) {
	s := &Service{}
	s.AllowForSession("deploy", "")      // AlwaysAsk 写工具
	s.AllowForSession("file_write", "")  // 普通写工具
	capAlwaysAsk := Capability{AlwaysAsk: true}
	// AlwaysAsk 写工具：只读拦截先于会话授权（修前 rule.session.allow）
	if d := s.Check(ctx, "deploy", nil, ModeReadOnly, capAlwaysAsk); d.Behavior != Deny || d.RuleID != "mode.read_only" {
		t.Fatalf("只读档+会话钥匙+AlwaysAsk 写工具应拒（敏感度倒挂已修）: %+v", d)
	}
	// 普通写工具：同参（照旧 deny）
	if d := s.Check(ctx, "file_write", map[string]any{"path": "a"}, ModeReadOnly, Capability{}); d.Behavior != Deny || d.RuleID != "mode.read_only" {
		t.Fatalf("只读档+会话钥匙+普通写工具应拒: %+v", d)
	}
	// 只读档之外钥匙照常放行（既有语义不弱化）
	if d := s.Check(ctx, "deploy", nil, ModeDefault, capAlwaysAsk); d.Behavior != Allow || d.RuleID != "rule.session.allow" {
		t.Fatalf("默认档钥匙应放行: %+v", d)
	}
	// 只读工具不受影响：只读档放行、钥匙语义不变
	s.AllowForSession("webfetch", "")
	if d := s.Check(ctx, "webfetch", nil, ModeReadOnly, Capability{ReadOnly: true}); d.Behavior != Allow {
		t.Fatalf("只读工具在只读档应放行: %+v", d)
	}
}

// TestIssue183MixedGlobPrefixNotDead guardx#183：`:*` 前缀形态里 prefix 自带
// `*`（`*/etc/passwd:*`）此前两分支都不命中——deny 静默死字零告警。修复后
// 退化为 glob 前缀匹配 + OnConfigWarn fail-loud。
func TestIssue183MixedGlobPrefixNotDead(t *testing.T) {
	var warns []string
	s := &Service{
		ProjectRules: Ruleset{Deny: []Rule{{ToolName: "bash", Content: "*/etc/passwd:*"}}},
		OnConfigWarn: func(m string) { warns = append(warns, m) },
	}
	// 修复前 `cat /etc/passwd` 原样放行（yolo/白名单下无确认）。
	for _, cmd := range []string{"cat /etc/passwd", "wc -l /etc/passwd extra", "*/etc/passwd"} {
		if d := s.Check(ctx, "bash", cmd, ModeYolo, Capability{}); d.Behavior != Deny || d.RuleID != "rule.project.deny" {
			t.Fatalf("混用形态的 deny 不得是死字: %q -> %+v", cmd, d)
		}
	}
	// fail-loud：混用形态触发 OnConfigWarn。
	if len(warns) == 0 {
		t.Fatal("混用形态应触发 OnConfigWarn（fail-loud）")
	}
	// 两种读法的并集：glob 前缀读法（尾 `:*` 当形态标记）兜住 `cat /etc/passwd`；
	// 整串通读法（尾 `:*` 当「: + 任意」）兜住含冒号形态——deny 侧取更宽。
	if d := s.Check(ctx, "bash", "grep /etc/passwd:evil", ModeYolo, Capability{}); d.Behavior != Deny {
		t.Fatalf("整串通读法应兜住含冒号形态: %+v", d)
	}
	// 两种读法都不命中的命令照旧放行。
	if d := s.Check(ctx, "bash", "cat /etc/shadow", ModeYolo, Capability{}); d.Behavior != Allow {
		t.Fatalf("混用规则不得退化为无界匹配: %+v", d)
	}
	// 对照：不混用的前缀/通配形态不受影响。
	s2 := &Service{ProjectRules: Ruleset{
		Deny: []Rule{{ToolName: "bash", Content: "rm -rf:*"}, {ToolName: "bash", Content: "*shadow*"}},
	}}
	if d := s2.Check(ctx, "bash", "rm -rf /", ModeYolo, Capability{}); d.Behavior != Deny {
		t.Fatalf("非混用前缀形态不受影响: %+v", d)
	}
	if d := s2.Check(ctx, "bash", "cat /etc/shadow", ModeYolo, Capability{}); d.Behavior != Deny {
		t.Fatalf("非混用通配形态不受影响: %+v", d)
	}
	if d := s2.Check(ctx, "bash", "ls /etc", ModeYolo, Capability{}); d.Behavior != Allow {
		t.Fatalf("无命中的命令照旧放行: %+v", d)
	}
}
