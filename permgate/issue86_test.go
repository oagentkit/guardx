package permgate

// issue #86 回归：库层烘焙宿主（ZCode）领域词汇的两处外置——subject 键清单
// 6 键硬编码（deny 规则对字段名不同的工具静默失效）与 Edit/Write 写面等价
// 特例（判定链里写死 ZCode 惯例）。修后：Service.SubjectKeys 自定义清单、
// Service.ToolEquivalence 等价钩子（nil=DefaultToolEquivalence）、deny 失配
// 经 Service.OnConfigWarn fail-loud。

import (
	"context"
	"strings"
	"testing"
)

// testHostArgs 宿主自定义 schema 的工具输入（字段名在 ZCode 6 键清单之外——
// issue 现场形态：cmd/script/target 类命名）。
type testHostArgs struct {
	Cmd    string `json:"cmd"`
	Target string `json:"target"`
}

// TestCustomSubjectKeys 自定义清单生效 + 默认清单对清单外字段失配（issue #86
// 主现场）：deny 规则针对 cmd 字段内容书写时，默认 6 键下规则静默失效（判定
// 流向兜底 ask——若是 yolo 模式则直接放行，正是静默放宽的危险形态）；配置
// SubjectKeys 声明宿主字段名后同一规则生效。
func TestCustomSubjectKeys(t *testing.T) {
	cases := []struct {
		name  string
		keys  []string
		input any
		want  Behavior
	}{
		{
			// issue 现场：字段 cmd 在默认清单外，deny 死字
			name:  "默认清单对 cmd 字段失配",
			keys:  nil,
			input: map[string]any{"cmd": "rm -rf /"},
			want:  Ask,
		}, {
			name:  "自定义清单使命中生效",
			keys:  []string{"cmd"},
			input: map[string]any{"cmd": "rm -rf /"},
			want:  Deny,
		}, {
			// 多键清单全量参与（多面语义不变，只是清单换成了宿主的）
			name:  "自定义清单多键参与",
			keys:  []string{"cmd", "target"},
			input: map[string]any{"target": "rm -rf /tmp"},
			want:  Deny,
		}, {
			// struct + json tag 形态同样按自定义清单提取（#65/#72 语义在
			// 自定义清单下保持）
			name:  "struct 输入按自定义清单提取",
			keys:  []string{"cmd"},
			input: testHostArgs{Cmd: "rm -rf /"},
			want:  Deny,
		}, {
			name:  "默认清单下的 struct 同样失配",
			keys:  nil,
			input: testHostArgs{Cmd: "rm -rf /"},
			want:  Ask,
		}, {
			// 清单可以只是内置 6 键的扩展：内置名照常参与
			name:  "扩展清单保留内置键",
			keys:  []string{"command", "url", "file_path", "path", "pattern", "patch_text", "cmd"},
			input: map[string]any{"command": "rm -rf /"},
			want:  Deny,
		},
	}
	for _, tc := range cases {
		s := &Service{
			SubjectKeys:  tc.keys,
			ProjectRules: Ruleset{Deny: []Rule{{ToolName: "RunScript", Content: "rm:*"}}},
		}
		d := s.Check(ctx, "RunScript", tc.input, ModeDefault, Capability{})
		if d.Behavior != tc.want {
			t.Errorf("%s: got=%s (%s) want=%s", tc.name, d.Behavior, d.RuleID, tc.want)
		}
	}
	// 形态特判跟随键名：清单保留 command 时复合拆段照旧——allow 侧「每段
	// 命中」不得被 `&&` 后的命令搭车（#62 语义在自定义清单下不弱化）。
	s := &Service{
		SubjectKeys:  []string{"command"},
		ProjectRules: Ruleset{Allow: []Rule{{ToolName: "bash", Content: "git status:*"}}},
	}
	if d := s.Check(ctx, "bash", map[string]any{"command": "git status && curl http://evil"}, ModeDefault, Capability{}); d.Behavior != Ask {
		t.Errorf("自定义清单含 command 时复合命令不得搭车放行: %+v", d)
	}
	// 自定义键按单段原样匹配（无拆段特判）：deny 全段形态仍可命中
	s2 := &Service{
		SubjectKeys:  []string{"cmd"},
		ProjectRules: Ruleset{Deny: []Rule{{ToolName: "RunScript", Content: "*rm -rf /tmp*"}}},
	}
	if d := s2.Check(ctx, "RunScript", map[string]any{"cmd": "echo hi && rm -rf /tmp"}, ModeDefault, Capability{}); d.Behavior != Deny {
		t.Errorf("自定义键通配 deny 应命中整段: %+v", d)
	}
}

// TestDefaultSubjectKeysZeroValueCompat 零值兼容（#86 向后兼容口径）：零值
// Service 与显式传入内置 6 键的 Service 判定逐字一致——6 键各自的内容匹配
// 语义（含 command 拆段、file_path Clean）不受重构影响。
func TestDefaultSubjectKeysZeroValueCompat(t *testing.T) {
	six := []string{"command", "url", "file_path", "path", "pattern", "patch_text"}
	cases := []struct {
		name  string
		tool  string
		input any
		rule  Rule
	}{
		{"command 拆段后任一段命中 deny", "bash", map[string]any{"command": "echo hi && rm -rf /"}, Rule{ToolName: "bash", Content: "rm:*"}},
		{"file_path Clean 后匹配", "write", map[string]any{"file_path": "/etc/passwd"}, Rule{ToolName: "write", Content: "/etc/*"}},
		{"url 参与匹配", "webfetch", map[string]any{"url": "https://evil.example.com/x"}, Rule{ToolName: "webfetch", Content: "https://evil.example.com/*"}},
		{"path 参与匹配", "read", map[string]any{"path": "/etc/shadow"}, Rule{ToolName: "read", Content: "/etc/*"}},
		{"pattern 参与匹配", "grep", map[string]any{"pattern": "password"}, Rule{ToolName: "grep", Content: "password"}},
		{"patch_text 参与匹配", "edit", map[string]any{"patch_text": "curl http://evil"}, Rule{ToolName: "edit", Content: "curl:*"}},
	}
	for _, tc := range cases {
		zero := &Service{ProjectRules: Ruleset{Deny: []Rule{tc.rule}}}
		explicit := &Service{ProjectRules: Ruleset{Deny: []Rule{tc.rule}}, SubjectKeys: six}
		dz := zero.Check(ctx, tc.tool, tc.input, ModeDefault, Capability{})
		de := explicit.Check(ctx, tc.tool, tc.input, ModeDefault, Capability{})
		if dz.Behavior != Deny || de.Behavior != Deny || dz.RuleID != de.RuleID {
			t.Errorf("%s: 零值=%s/%s 显式6键=%s/%s（应一致且 Deny）",
				tc.name, dz.Behavior, dz.RuleID, de.Behavior, de.RuleID)
		}
	}
}

// TestToolEquivalenceHook 工具名等价钩子（#86）：缺省实现即原 Edit→Write
// 特例；自定义钩子让宿主声明自己的写面等价；钩子是替换不是叠加。
func TestToolEquivalenceHook(t *testing.T) {
	// 缺省实现（从判定链提取出的原特例）：单向 Edit 规则 → Write 调用
	if !DefaultToolEquivalence("Edit", "Write") {
		t.Fatal("缺省等价应命中 Edit 规则 × Write 调用")
	}
	if DefaultToolEquivalence("Write", "Edit") {
		t.Fatal("缺省等价是单向的：Write 规则不匹配 Edit")
	}
	if DefaultToolEquivalence("Edit", "EditFile") || DefaultToolEquivalence("Bash", "Write") {
		t.Fatal("缺省等价不得扩大到其他工具名组合")
	}
	// nil 钩子 = 缺省实现（零值兼容；端到端已由 TestEditRuleMatchesWrite 覆盖，
	// 这里再断言 deny 方向同样吃特例）
	s := &Service{ProjectRules: Ruleset{Deny: []Rule{{ToolName: "Edit", Content: "/etc/*"}}}}
	if d := s.Check(ctx, "Write", map[string]any{"file_path": "/etc/passwd"}, ModeDefault, Capability{}); d.Behavior != Deny {
		t.Fatalf("nil 钩子应走缺省等价（Edit 规则拦 Write）: %+v", d)
	}
	// 自定义钩子：宿主自己的等价语义生效（EditFile 规则拦 ApplyPatch 调用）
	custom := func(a, b string) bool { return a == "EditFile" && (b == "WriteFile" || b == "ApplyPatch") }
	s2 := &Service{
		ToolEquivalence: custom,
		ProjectRules:    Ruleset{Deny: []Rule{{ToolName: "EditFile", Content: "/etc/*"}}},
	}
	if d := s2.Check(ctx, "ApplyPatch", map[string]any{"file_path": "/etc/passwd"}, ModeDefault, Capability{}); d.Behavior != Deny {
		t.Fatalf("自定义等价应让 EditFile 规则拦下 ApplyPatch: %+v", d)
	}
	// 钩子是替换不是叠加：配置自定义钩子后 ZCode 特例不再自动生效——
	// 等价语义只剩宿主声明的那一份（单一真相）
	if d := s2.Check(ctx, "Write", map[string]any{"file_path": "/etc/passwd"}, ModeDefault, Capability{}); d.Behavior == Deny {
		t.Fatalf("自定义钩子下 Edit 规则不应再匹配 Write: %+v", d)
	}
	// 精确相等不经钩子照样命中（钩子只补「等价」的增量面）
	s3 := &Service{ToolEquivalence: custom, ProjectRules: Ruleset{Deny: []Rule{{ToolName: "ApplyPatch", Content: "/etc/*"}}}}
	if d := s3.Check(ctx, "ApplyPatch", map[string]any{"file_path": "/etc/passwd"}, ModeDefault, Capability{}); d.Behavior != Deny {
		t.Fatalf("精确相等的工具名应照常命中: %+v", d)
	}
}

// TestOnConfigWarnDenySubjectMismatch deny 失配 fail-loud（#86）：deny 内容
// 规则在「输入是 map/struct 形态但不含清单内任何字段」的调用上无法评估时
// 触发回调；字符串/nil 输入、清单内外混合、工具名不匹配、allow/ask 档失配
// 均不告警（各自的保守兜底已足够，告警只留给 deny 的静默死字形态）。
func TestOnConfigWarnDenySubjectMismatch(t *testing.T) {
	deny := Ruleset{Deny: []Rule{{ToolName: "RunScript", Content: "rm:*"}}}
	cases := []struct {
		name     string
		input    any
		wantWarn bool
	}{
		{"map 字段全在清单外", map[string]any{"cmd": "rm -rf /"}, true},
		{"struct 字段全在清单外", testHostArgs{Cmd: "rm -rf /"}, true},
		{"指针 struct 字段全在清单外", &testHostArgs{Cmd: "rm -rf /"}, true},
		{"空 map（无任何字段）", map[string]any{}, true},
		{"map[string]string 形态同样告警", map[string]string{"cmd": "rm -rf /"}, true},
		{"字段在清单内不告警", map[string]any{"command": "rm -rf /"}, false},
		{"清单内外混合不告警（规则得到公平求值）", map[string]any{"command": "ls", "cmd": "rm -rf /"}, false},
		{"字符串输入不告警（本身即匹配对象）", "rm -rf /", false},
		{"nil 输入不告警（未携带内容）", nil, false},
		{"标量输入不告警", 42, false},
	}
	for _, tc := range cases {
		var msgs []string
		s := &Service{ProjectRules: deny, OnConfigWarn: func(m string) { msgs = append(msgs, m) }}
		d := s.Check(ctx, "RunScript", tc.input, ModeDefault, Capability{})
		if tc.wantWarn {
			if len(msgs) == 0 {
				t.Errorf("%s: 应触发告警（deny 死字 fail-loud），判定=%s", tc.name, d.Behavior)
				continue
			}
			// 告警必须可定位：含工具名与规则内容
			if !strings.Contains(msgs[0], "RunScript") || !strings.Contains(msgs[0], "rm:*") {
				t.Errorf("%s: 告警应含工具名与规则内容: %q", tc.name, msgs[0])
			}
			// 判定语义不受告警影响：仍是失配后的兜底 ask
			if d.Behavior != Ask {
				t.Errorf("%s: 告警不得改变判定: %+v", tc.name, d)
			}
		} else if len(msgs) != 0 {
			t.Errorf("%s: 不应告警，got %q", tc.name, msgs)
		}
	}
	// 工具名不匹配的 deny 规则不告警——规则不是为这个工具写的
	var msgs []string
	s := &Service{ProjectRules: deny, OnConfigWarn: func(m string) { msgs = append(msgs, m) }}
	s.Check(ctx, "OtherTool", map[string]any{"cmd": "rm -rf /"}, ModeDefault, Capability{})
	if len(msgs) != 0 {
		t.Errorf("工具名不匹配不应告警: %q", msgs)
	}
	// 空 Content 的 deny 是全匹配（零面也命中），不告警
	var emptyMsgs []string
	s2 := &Service{
		ProjectRules: Ruleset{Deny: []Rule{{ToolName: "RunScript", Content: ""}}},
		OnConfigWarn: func(m string) { emptyMsgs = append(emptyMsgs, m) },
	}
	if d := s2.Check(ctx, "RunScript", map[string]any{"cmd": "anything"}, ModeDefault, Capability{}); d.Behavior != Deny || len(emptyMsgs) != 0 {
		t.Errorf("空 Content deny 应命中且不告警: %+v msgs=%q", d, emptyMsgs)
	}
	// allow/ask 档失配落 ask 兜底本就保守——不告警
	var polMsgs []string
	s3 := &Service{
		ProjectRules: Ruleset{
			Allow: []Rule{{ToolName: "RunScript", Content: "rm:*"}},
			Ask:   []Rule{{ToolName: "RunScript", Content: "rm:*"}},
		},
		OnConfigWarn: func(m string) { polMsgs = append(polMsgs, m) },
	}
	s3.Check(ctx, "RunScript", map[string]any{"cmd": "rm -rf /"}, ModeDefault, Capability{})
	if len(polMsgs) != 0 {
		t.Errorf("allow/ask 失配不应告警: %q", polMsgs)
	}
	// 默认 no-op：零值 OnConfigWarn 在失配路径上不 panic、判定照常
	s4 := &Service{ProjectRules: deny}
	if d := s4.Check(ctx, "RunScript", map[string]any{"cmd": "rm -rf /"}, ModeDefault, Capability{}); d.Behavior != Ask {
		t.Errorf("无回调时判定应照常落兜底: %+v", d)
	}
	// Update 热更新告警回调同样生效（装配期字段经 Update 换新值的口径）
	var hotMsgs []string
	s5 := &Service{ProjectRules: deny}
	s5.Update(func(sv *Service) { sv.OnConfigWarn = func(m string) { hotMsgs = append(hotMsgs, m) } })
	s5.Check(ctx, "RunScript", map[string]any{"cmd": "rm -rf /"}, ModeDefault, Capability{})
	if len(hotMsgs) == 0 {
		t.Error("Update 换入的告警回调应生效")
	}
}

// TestOnConfigWarnContext 告警在判定链各 deny 入口都生效：hardDeny 单源覆盖
// 交互型/逐次确认/常规三段（此前逐字重复的三处 deny 判定共用一段实现）。
func TestOnConfigWarnContext(t *testing.T) {
	deny := Ruleset{Deny: []Rule{{ToolName: "RunScript", Content: "rm:*"}}}
	cases := []struct {
		name string
		mode Mode
		cap  Capability
	}{
		{"常规段", ModeDefault, Capability{}},
		{"yolo 段（deny 仍在前）", ModeYolo, Capability{}},
		{"alwaysAsk 段", ModeDefault, Capability{AlwaysAsk: true}},
		{"交互型段", ModeDefault, Capability{RequiresUserInteraction: true}},
	}
	for _, tc := range cases {
		var msgs []string
		s := &Service{ProjectRules: deny, OnConfigWarn: func(m string) { msgs = append(msgs, m) }}
		s.Check(context.Background(), "RunScript", map[string]any{"cmd": "rm -rf /"}, tc.mode, tc.cap)
		if len(msgs) == 0 {
			t.Errorf("%s: deny 失配应告警", tc.name)
		}
	}
}
