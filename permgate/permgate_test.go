package permgate

import (
	"context"
	"sync"
	"testing"
)

var ctx = context.Background()

func TestPriorityChain(t *testing.T) {
	s := &Service{
		DisallowedTools: map[string]bool{"danger": true},
		AllowedTools:    map[string]bool{"safe": true},
		ProjectRules: Ruleset{
			Deny:  []Rule{{ToolName: "bash", Content: "rm -rf:*"}},
			Ask:   []Rule{{ToolName: "bash", Content: "git push:*"}},
			Allow: []Rule{{ToolName: "webfetch", Content: "https://docs.example.com/*"}},
		},
	}
	cases := []struct {
		name string
		tool string
		in   any
		mode Mode
		cap  Capability
		want Behavior
		rule string
	}{
		{"交互型工具", "ask_user", nil, ModeDefault, Capability{RequiresUserInteraction: true}, Ask, "tool.userInteraction"},
		{"交互型被硬禁", "danger", nil, ModeDefault, Capability{RequiresUserInteraction: true}, Deny, "rule.disallowedTools"},
		{"alwaysAsk 压过 yolo", "deploy", nil, ModeYolo, Capability{AlwaysAsk: true}, Ask, "tool.alwaysAsk"},
		{"alwaysAsk 被项目 deny 压过", "bash", "rm -rf /tmp", ModeDefault, Capability{AlwaysAsk: true}, Deny, "rule.project.deny"},
		{"alwaysAsk 未授权", "deploy", nil, ModeDefault, Capability{AlwaysAsk: true}, Ask, "tool.alwaysAsk"},
		{"yolo 直通", "bash", "ls -la", ModeYolo, Capability{}, Allow, "mode.yolo"},
		{"yolo 压不过硬禁", "danger", nil, ModeYolo, Capability{}, Deny, "rule.disallowedTools"},
		{"项目 deny", "bash", "rm -rf /tmp", ModeDefault, Capability{}, Deny, "rule.project.deny"},
		{"项目 ask", "bash", "git push origin", ModeDefault, Capability{}, Ask, "rule.project.ask"},
		{"只读模式放行只读", "read", nil, ModeReadOnly, Capability{ReadOnly: true}, Allow, "mode.read_only"},
		{"只读模式拦写入", "write", map[string]any{"file_path": "a"}, ModeReadOnly, Capability{}, Deny, "mode.read_only"},
		{"只读模式拒 alwaysAsk 写入", "deploy", nil, ModeReadOnly, Capability{AlwaysAsk: true}, Deny, "mode.read_only"},
		{"只读模式拒项目 ask 的写入", "bash", "git push origin", ModeReadOnly, Capability{}, Deny, "mode.read_only"},
		{"只读模式不拦 alwaysAsk 的只读工具", "read", nil, ModeReadOnly, Capability{AlwaysAsk: true, ReadOnly: true}, Ask, "tool.alwaysAsk"},
		{"项目 allow", "webfetch", map[string]any{"url": "https://docs.example.com/a"}, ModeDefault, Capability{}, Allow, "rule.project.allow"},
	}
	for _, tc := range cases {
		got := s.Check(ctx, tc.tool, tc.in, tc.mode, tc.cap)
		if got.Behavior != tc.want || got.RuleID != tc.rule {
			t.Errorf("%s: got=%s/%s want=%s/%s", tc.name, got.Behavior, got.RuleID, tc.want, tc.rule)
		}
	}
	// 逐个精确断言关键档位
	if d := s.Check(ctx, "bash", "git status", ModeDefault, Capability{}); d.Behavior != Ask || d.RuleID != "mode.default" {
		t.Fatalf("git status 应落兜底 ask: %+v", d)
	}
	if d := s.Check(ctx, "bash", "rm -rf /tmp", ModeYolo, Capability{}); d.Behavior != Deny || d.RuleID != "rule.project.deny" {
		t.Fatalf("yolo 在项目 deny 上仍应拦（且黑名单/项目拒绝先于 yolo）: %+v", d)
	}
}

func TestSessionGrantLifecycle(t *testing.T) {
	s := &Service{}
	cap := Capability{AlwaysAsk: true}
	if d := s.Check(ctx, "deploy", nil, ModeDefault, cap); d.Behavior != Ask {
		t.Fatalf("未授权应 ask: %+v", d)
	}
	s.AllowForSession("deploy", "")
	if d := s.Check(ctx, "deploy", nil, ModeDefault, cap); d.Behavior != Allow || d.RuleID != "rule.session.allow" {
		t.Fatalf("会话授权应放行: %+v", d)
	}
	// 内容限定的会话授权：别的命令仍 ask
	s.ResetSession()
	s.AllowForSession("bash", "git status:*")
	if d := s.Check(ctx, "bash", "git status", ModeDefault, Capability{}); d.Behavior != Allow {
		t.Fatalf("命中内容应放行: %+v", d)
	}
	if d := s.Check(ctx, "bash", "git push", ModeDefault, Capability{}); d.Behavior == Allow {
		t.Fatalf("未命中内容不应放行: %+v", d)
	}
}

func TestRuleContentMatching(t *testing.T) {
	cases := []struct {
		content string
		sub     string
		want    bool
	}{
		{"", "anything", true},                       // 空模式=全匹配
		{"git status", "git status", true},           // 精确
		{"git status", "git statusx", false},         // 不等
		{"git status:*", "git status", true},         // 前缀=本体
		{"git status:*", "git status --short", true}, // 前缀+空格
		{"git status:*", "git statusx", false},       // 前缀须边界
		{"npm run *", "npm run build", true},         // 通配
		{"npm run *", "npm test", false},             // 通配不中
		{"web/**/*.vue", "web/src/a.vue", true},      // 跨段通配
		{"git status", "", false},                    // 无匹配对象
	}
	for _, tc := range cases {
		var faces []subjectFace
		if tc.sub != "" {
			faces = []subjectFace{{tc.sub}}
		}
		// 单段面上量词无差别：三种极性结果一致
		for _, pol := range []Behavior{Allow, Ask, Deny} {
			if got := matchRuleContent(tc.content, faces, pol); got != tc.want {
				t.Errorf("content=%q sub=%q pol=%s: got %v want %v", tc.content, tc.sub, pol, got, tc.want)
			}
		}
	}
	// 空模式对零面输入同样全匹配（该工具全部调用）
	if !matchRuleContent("", nil, Deny) {
		t.Fatal("空模式应全匹配")
	}
}

func TestSubjectsExtraction(t *testing.T) {
	if got := subjects("raw command", "x"); len(got) != 1 || len(got[0]) != 1 || got[0][0] != "raw command" {
		t.Fatalf("字符串输入: %v", got)
	}
	m := map[string]any{"command": "ls", "file_path": "a"}
	if got := subjects(m, "bash"); got[0][0] != "ls" {
		t.Fatalf("command 优先: %v", got)
	}
	m2 := map[string]any{"file_path": "/tmp/x"}
	if got := subjects(m2, "read"); got[0][0] != "/tmp/x" {
		t.Fatalf("file_path: %v", got)
	}
	if got := subjects(42, "x"); got != nil {
		t.Fatalf("未知形态: %v", got)
	}
}

func TestEditRuleMatchesWrite(t *testing.T) {
	s := &Service{ProjectRules: Ruleset{Allow: []Rule{{ToolName: "Edit", Content: "/src/*"}}}}
	if d := s.Check(ctx, "Write", map[string]any{"file_path": "/src/a.go"}, ModeDefault, Capability{}); d.Behavior != Allow {
		t.Fatalf("Edit 规则应匹配 Write: %+v", d)
	}
	if d := s.Check(ctx, "Write", map[string]any{"file_path": "/etc/passwd"}, ModeDefault, Capability{}); d.Behavior == Allow {
		t.Fatalf("内容不匹配: %+v", d)
	}
}

func TestPreapproveHook(t *testing.T) {
	s := &Service{Preapprove: func(ctx context.Context, tool string, input any) (string, bool) {
		if u, ok := input.(map[string]any)["url"].(string); ok && u == "https://docs.example.com" {
			return "tool.webfetch.preapproved", true
		}
		return "", false
	}}
	if d := s.Check(ctx, "webfetch", map[string]any{"url": "https://docs.example.com"}, ModeDefault, Capability{}); d.Behavior != Allow || d.RuleID != "tool.webfetch.preapproved" {
		t.Fatalf("预批应放行: %+v", d)
	}
	if d := s.Check(ctx, "webfetch", map[string]any{"url": "https://other.com"}, ModeDefault, Capability{}); d.Behavior != Ask {
		t.Fatalf("未预批应落兜底: %+v", d)
	}
	// 只读模式压过预批（写入类预批也不行——位次设计）
	s2 := &Service{Preapprove: s.Preapprove}
	if d := s2.Check(ctx, "webfetch", map[string]any{"url": "https://docs.example.com"}, ModeReadOnly, Capability{ReadOnly: true}); d.Behavior != Allow {
		t.Fatalf("只读模式+只读工具应放行: %+v", d)
	}
	if d := s2.Check(ctx, "webfetch", map[string]any{"url": "https://docs.example.com"}, ModeReadOnly, Capability{}); d.Behavior != Deny {
		t.Fatalf("只读模式压过预批（非只读工具拦下）: %+v", d)
	}
}

// TestWildcardPathTraversalDenied 回归（第六轮审计）：wildcard 路径规则可被
// `..` 穿越绕过——file_path/path 类 subject 匹配前 Clean，"/repo/data/../../etc/passwd"
// 归一为 "/etc/passwd" 后不再命中 "/repo/data/*"（fail-closed，落 Ask 裁决）。
func TestWildcardPathTraversalDenied(t *testing.T) {
	s := &Service{
		ProjectRules: Ruleset{
			Allow: []Rule{{ToolName: "write", Content: "/repo/data/*"}},
		},
	}
	in := map[string]any{"file_path": "/repo/data/../../etc/passwd"}
	d := s.Check(ctx, "write", in, ModeDefault, Capability{})
	if d.Behavior == Allow {
		t.Fatalf("穿越路径不应命中 allow 规则: %+v", d)
	}
	// 正常子路径仍命中
	d2 := s.Check(ctx, "write", map[string]any{"file_path": "/repo/data/sub/a.txt"}, ModeDefault, Capability{})
	if d2.Behavior != Allow {
		t.Fatalf("正常子路径应放行: %+v", d2)
	}
}

// TestReadOnlyModeDeniesInsteadOfAsk 回归（issue #24）：只读档对写入类工具是
// 「禁」不是「问」——alwaysAsk 与 project ask 两处「问」都不得把它短路成 Ask
// （否则只读退化成「换个姿势问」）。
func TestReadOnlyModeDeniesInsteadOfAsk(t *testing.T) {
	s := &Service{
		ProjectRules: Ruleset{
			Ask: []Rule{{ToolName: "bash", Content: "git push:*"}},
		},
	}
	// alwaysAsk 段：只读档直接拒
	if d := s.Check(ctx, "deploy", nil, ModeReadOnly, Capability{AlwaysAsk: true}); d.Behavior != Deny || d.RuleID != "mode.read_only" {
		t.Fatalf("只读+alwaysAsk 应直接拒: %+v", d)
	}
	// project ask 段：同一条规则在只读档是「禁」
	if d := s.Check(ctx, "bash", "git push origin", ModeReadOnly, Capability{}); d.Behavior != Deny || d.RuleID != "mode.read_only" {
		t.Fatalf("只读+项目ask 应直接拒: %+v", d)
	}
	// 默认档不变：仍是「问」
	if d := s.Check(ctx, "deploy", nil, ModeDefault, Capability{AlwaysAsk: true}); d.Behavior != Ask || d.RuleID != "tool.alwaysAsk" {
		t.Fatalf("默认档+alwaysAsk 应问: %+v", d)
	}
	if d := s.Check(ctx, "bash", "git push origin", ModeDefault, Capability{}); d.Behavior != Ask || d.RuleID != "rule.project.ask" {
		t.Fatalf("默认档+项目ask 应问: %+v", d)
	}
	// 只读工具在只读档照常放行
	if d := s.Check(ctx, "read", nil, ModeReadOnly, Capability{ReadOnly: true}); d.Behavior != Allow || d.RuleID != "mode.read_only" {
		t.Fatalf("只读+只读工具应放行: %+v", d)
	}
	// 会话授权是用户已经给出的决定（放行），不是一次「问」——保持不看模式
	s.AllowForSession("deploy", "")
	if d := s.Check(ctx, "deploy", nil, ModeReadOnly, Capability{AlwaysAsk: true}); d.Behavior != Allow || d.RuleID != "rule.session.allow" {
		t.Fatalf("只读+会话授权应放行: %+v", d)
	}
	// 交互型工具不在拦截范围内：它不产生副作用（plan 档要靠它提问）
	if d := s.Check(ctx, "ask_user", nil, ModeReadOnly, Capability{RequiresUserInteraction: true}); d.Behavior != Ask {
		t.Fatalf("只读+交互型应问: %+v", d)
	}
}

// TestReadOnlyWhitelistBreakGlass 回归（issue #58）：只读档默认禁写，但配置
// 白名单是「比模式更强的信任」——运维显式加白的单个写工具压过只读档
// （break-glass 位次），下游不必再在 permgate 之外私设本地 override。
// 硬禁（disallowed/project deny）仍压过白名单——白名单不是绕禁的后门。
func TestReadOnlyWhitelistBreakGlass(t *testing.T) {
	s := &Service{
		AllowedTools: map[string]bool{"set_permission_mode": true},
		ProjectRules: Ruleset{
			Allow: []Rule{{ToolName: "backup_writer"}},
			Deny:  []Rule{{ToolName: "dangerous_writer"}},
		},
	}
	// 主诉求：只读档 + 白名单写工具 → 放行，RuleID 标白名单（审计可辨）
	if d := s.Check(ctx, "set_permission_mode", nil, ModeReadOnly, Capability{}); d.Behavior != Allow || d.RuleID != "rule.allowedTools" {
		t.Fatalf("只读+白名单写工具应放行: %+v", d)
	}
	// 未加白的写工具：只读档照旧禁（#24 语义不弱化）
	if d := s.Check(ctx, "backup_writer", nil, ModeReadOnly, Capability{}); d.Behavior != Deny || d.RuleID != "mode.read_only" {
		t.Fatalf("只读+未加白写工具应拒（project allow 不构成 break-glass）: %+v", d)
	}
	// 硬禁压过白名单
	if d := s.Check(ctx, "dangerous_writer", nil, ModeReadOnly, Capability{}); d.Behavior != Deny || d.RuleID != "rule.project.deny" {
		t.Fatalf("只读+白名单+项目deny 应拒: %+v", d)
	}
	s2 := &Service{AllowedTools: map[string]bool{"danger": true}, DisallowedTools: map[string]bool{"danger": true}}
	if d := s2.Check(ctx, "danger", nil, ModeDefault, Capability{}); d.Behavior != Deny || d.RuleID != "rule.disallowedTools" {
		t.Fatalf("disallowed 压过白名单: %+v", d)
	}
	// 只读工具 + 白名单：照常放行（RuleID 标白名单，位次在前）
	s3 := &Service{AllowedTools: map[string]bool{"read": true}}
	if d := s3.Check(ctx, "read", nil, ModeReadOnly, Capability{ReadOnly: true}); d.Behavior != Allow {
		t.Fatalf("只读+白名单只读工具应放行: %+v", d)
	}
	// 白名单压过 project ask（显式信任强于「问」）
	s4 := &Service{
		AllowedTools: map[string]bool{"bash": true},
		ProjectRules: Ruleset{Ask: []Rule{{ToolName: "bash", Content: "git push:*"}}},
	}
	if d := s4.Check(ctx, "bash", "git push origin", ModeDefault, Capability{}); d.Behavior != Allow || d.RuleID != "rule.allowedTools" {
		t.Fatalf("白名单应压过项目 ask: %+v", d)
	}
}

// TestSplitCommand 复合命令操作符拆段（issue #62）：`;` `&&` `||` `|` 换行；
// 引号内与反斜杠转义不拆；空段丢弃。
func TestSplitCommand(t *testing.T) {
	cases := []struct {
		cmd  string
		want []string
	}{
		{"git status", []string{"git status"}},                             // 无操作符：单段原样
		{"  git status  ", []string{"git status"}},                         // 首尾空白剥除
		{"git status && curl evil", []string{"git status", "curl evil"}},   // &&
		{"git status||curl evil", []string{"git status", "curl evil"}},     // ||
		{"a;b", []string{"a", "b"}},                                        // ;
		{"a | b", []string{"a", "b"}},                                      // 管道
		{"a\nb", []string{"a", "b"}},                                       // 换行
		{"a\r\nb", []string{"a", "b"}},                                     // CRLF
		{"a && b || c ; d | e\nf", []string{"a", "b", "c", "d", "e", "f"}}, // 混合
		{`echo "a && b"`, []string{`echo "a && b"`}},                       // 双引号内不拆
		{`echo 'x;y'`, []string{`echo 'x;y'`}},                             // 单引号内不拆
		{`echo \; ok`, []string{`echo \; ok`}},                             // 反斜杠转义
		{"a & b", []string{"a & b"}},                                       // 单 & 是 URL 常客，不拆
		{"https://x.com/?a=1&b=2", []string{"https://x.com/?a=1&b=2"}},     // URL 完整
		{"&& curl evil", []string{"curl evil"}},                            // 前悬操作符：空段丢弃
		{"a &&", []string{"a"}},                                            // 尾悬操作符
		{"", nil},                                                          // 空
		{" \n\t", nil},                                                     // 全空白
	}
	for _, tc := range cases {
		got := splitCommand(tc.cmd)
		if len(got) != len(tc.want) {
			t.Errorf("splitCommand(%q) = %v, want %v", tc.cmd, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("splitCommand(%q) = %v, want %v", tc.cmd, got, tc.want)
				break
			}
		}
	}
}

// TestCompoundCommandNoAllowRide 回归（issue #62）：`git status && curl evil`
// 不得命中 `git status:*` 前缀 allow 搭车放行——allow/会话授权按「每段都在
// 名单里」求值；deny/ask 按「任一段命中」求值（复合命令混入危险段即拦）。
func TestCompoundCommandNoAllowRide(t *testing.T) {
	s := &Service{
		ProjectRules: Ruleset{
			Allow: []Rule{{ToolName: "bash", Content: "git status:*"}},
		},
	}
	// 纯命令照旧放行
	if d := s.Check(ctx, "bash", "git status", ModeDefault, Capability{}); d.Behavior != Allow {
		t.Fatalf("单条 git status 应放行: %+v", d)
	}
	// 复合搭车：操作符后的命令不在名单 → allow 失配 → 落兜底 ask
	if d := s.Check(ctx, "bash", "git status && curl http://evil", ModeDefault, Capability{}); d.Behavior != Ask || d.RuleID != "mode.default" {
		t.Fatalf("复合命令不得搭车放行: %+v", d)
	}
	// 换行形态同样不得搭车（此前 && 放行、\\n 拦截的双标源于操作符种类）
	if d := s.Check(ctx, "bash", "git status\ncurl http://evil", ModeDefault, Capability{}); d.Behavior != Ask {
		t.Fatalf("换行复合不得搭车放行: %+v", d)
	}
	// 每段都在名单 → 放行
	if d := s.Check(ctx, "bash", "git status && git status --short", ModeDefault, Capability{}); d.Behavior != Allow {
		t.Fatalf("全段命中应放行: %+v", d)
	}
	// 会话授权同语义：登记的前缀不罩操作符后的命令
	s2 := &Service{}
	s2.AllowForSession("bash", "git status:*")
	if d := s2.Check(ctx, "bash", "git status && curl http://evil", ModeDefault, Capability{}); d.Behavior != Ask {
		t.Fatalf("会话授权不得被复合命令搭车: %+v", d)
	}
	// deny 侧：任一段命中即拦（复合里混一段危险命令）
	s3 := &Service{
		ProjectRules: Ruleset{Deny: []Rule{{ToolName: "bash", Content: "curl:*"}}},
	}
	if d := s3.Check(ctx, "bash", "git status && curl http://evil", ModeDefault, Capability{}); d.Behavior != Deny || d.RuleID != "rule.project.deny" {
		t.Fatalf("复合含危险段应拒: %+v", d)
	}
	// 引号内的操作符不是分隔：`echo "a && b"` 仍是单段命令，echo 前缀照常放行
	s4 := &Service{
		ProjectRules: Ruleset{Allow: []Rule{{ToolName: "bash", Content: "echo:*"}}},
	}
	if d := s4.Check(ctx, "bash", `echo "a && b"`, ModeDefault, Capability{}); d.Behavior != Allow {
		t.Fatalf("引号内操作符不应拆段: %+v", d)
	}
}

// TestNewlineSeparatedDeny 回归（issue #71）：`rm\n-rf /` 不得绕过 `rm:*`
// 前缀 deny / `rm*` 通配 deny——换行同属命令分隔，前缀边界取任意空白，
// wildcard 跨行透明（(?s)）。
func TestNewlineSeparatedDeny(t *testing.T) {
	s := &Service{
		ProjectRules: Ruleset{Deny: []Rule{{ToolName: "bash", Content: "rm:*"}}},
	}
	if d := s.Check(ctx, "bash", "rm -rf /", ModeDefault, Capability{}); d.Behavior != Deny {
		t.Fatalf("单行 rm 应拒（存量回归）: %+v", d)
	}
	if d := s.Check(ctx, "bash", "rm\n-rf /", ModeDefault, Capability{}); d.Behavior != Deny || d.RuleID != "rule.project.deny" {
		t.Fatalf("换行 rm 应拒: %+v", d)
	}
	if d := s.Check(ctx, "bash", "cd /tmp\nrm -rf x", ModeDefault, Capability{}); d.Behavior != Deny {
		t.Fatalf("多行脚本含 rm 段应拒: %+v", d)
	}
	// 通配形态同样不得被换行绕过
	s2 := &Service{
		ProjectRules: Ruleset{Deny: []Rule{{ToolName: "bash", Content: "rm*"}}},
	}
	if d := s2.Check(ctx, "bash", "rm\n-rf /", ModeDefault, Capability{}); d.Behavior != Deny {
		t.Fatalf("通配 deny 对换行命令应命中: %+v", d)
	}
	// 直接对 matchRuleContent 断言：前缀边界认任意空白（含 \t、\v、\f）
	for _, sep := range []string{" ", "\t", "\n", "\v", "\f", "\r"} {
		if !matchRuleContent("git status:*", []subjectFace{{"git status" + sep + "--short"}}, Allow) {
			t.Errorf("前缀边界应认空白 %q", sep)
		}
	}
	if matchRuleContent("git status:*", []subjectFace{{"git statusx"}}, Allow) {
		t.Error("前缀不得 bleed 到更长 token")
	}
	// wildcard 对含换行的非命令面（如 patch_text）跨行透明
	if !wildcardMatch("a*b", "a\nb") {
		t.Error("通配应跨行匹配（(?s)）")
	}
}

// typedArgs 类型化入参（issue #65/#72 的反射提取对象）：字段名 + json tag +
// 匿名嵌入三种形态。
type typedArgs struct {
	Command string
	URL     string `json:"url"`
	Detail         // 匿名嵌入：file_path 藏在嵌入结构里
}

type Detail struct {
	FilePath string `json:"file_path"`
}

func TestTypedInputSubjects(t *testing.T) {
	// map[string]string：与 map[string]any 同构
	got := subjects(map[string]string{"command": "ls", "file_path": "/tmp/x"}, "bash")
	if len(got) != 2 || got[0][0] != "ls" || got[1][0] != "/tmp/x" {
		t.Fatalf("map[string]string 提取: %v", got)
	}
	// struct：字段名 + json tag + 匿名嵌入
	in := typedArgs{Command: "git status", URL: "https://a.com", Detail: Detail{FilePath: "/etc/passwd"}}
	got = subjects(in, "x")
	if len(got) != 3 || got[0][0] != "git status" || got[1][0] != "https://a.com" || got[2][0] != "/etc/passwd" {
		t.Fatalf("struct 提取: %v", got)
	}
	// 指针形态
	got = subjects(&in, "x")
	if len(got) != 3 {
		t.Fatalf("指针 struct 提取: %v", got)
	}
	// 其它 map 形态（值非 string 的不参与；string 值照常提取）
	if got := subjects(map[string]int{"command": 3}, "x"); got != nil {
		t.Fatalf("非 string 值不参与: %v", got)
	}
	got = subjects(map[string]any{"command": 42}, "x")
	if got != nil {
		t.Fatalf("map[string]any 非 string 值不参与: %v", got)
	}
	// nil 与未知形态
	if got := subjects(nil, "x"); got != nil {
		t.Fatalf("nil: %v", got)
	}
}

// TestTypedInputDenyNotBypassed 回归（issue #65/#72）：类型化输入使内容级
// deny 规则静默失配（deny 绕过，fail-open）——修后 map[string]string 与
// struct 形态都参与内容匹配。
func TestTypedInputDenyNotBypassed(t *testing.T) {
	s := &Service{
		ProjectRules: Ruleset{
			Deny: []Rule{
				{ToolName: "bash", Content: "rm:*"},
				{ToolName: "write", Content: "/etc/*"},
			},
		},
	}
	// 修复前：map[string]string 落 nil → deny 失配 → ask（fail-open）
	if d := s.Check(ctx, "bash", map[string]string{"command": "rm -rf /"}, ModeDefault, Capability{}); d.Behavior != Deny || d.RuleID != "rule.project.deny" {
		t.Fatalf("map[string]string 的 rm 应拒: %+v", d)
	}
	// struct + json tag 的路径 deny
	if d := s.Check(ctx, "write", map[string]string{"file_path": "/etc/passwd"}, ModeDefault, Capability{}); d.Behavior != Deny {
		t.Fatalf("map[string]string 的 /etc 写应拒: %+v", d)
	}
	in := struct {
		Command string
	}{"rm -rf /"}
	if d := s.Check(ctx, "bash", in, ModeDefault, Capability{}); d.Behavior != Deny {
		t.Fatalf("struct 的 rm 应拒: %+v", d)
	}
	// 复合拆段对类型化输入同样生效
	if d := s.Check(ctx, "bash", map[string]string{"command": "git status && rm -rf /"}, ModeDefault, Capability{}); d.Behavior != Deny {
		t.Fatalf("类型化复合命令含 rm 段应拒: %+v", d)
	}
	// 不含危险内容的类型化输入不受影响
	if d := s.Check(ctx, "bash", map[string]string{"command": "git status"}, ModeDefault, Capability{}); d.Behavior != Ask {
		t.Fatalf("普通命令照旧兜底 ask: %+v", d)
	}
}

// TestAllowForSessionDedup 回归（issue #70）：同 (tool, content) 重复登记折叠
// ——「规则表 = 授权真相」，SessionAllows 提供带锁快照的审计读口。
func TestAllowForSessionDedup(t *testing.T) {
	s := &Service{}
	s.AllowForSession("bash", "git status:*")
	s.AllowForSession("bash", "git status:*")
	s.AllowForSession("bash", "git status:*")
	if got := s.SessionAllows(); len(got) != 1 {
		t.Fatalf("重复登记应折叠为 1 条: %v", got)
	}
	s.AllowForSession("bash", "git push:*")
	s.AllowForSession("deploy", "")
	if got := s.SessionAllows(); len(got) != 3 {
		t.Fatalf("不同 tool/content 各占一条: %v", got)
	}
	// 快照可安全外部持有
	rules := s.SessionAllows()
	s.AllowForSession("bash", "npm:*")
	if len(rules) != 3 {
		t.Fatalf("快照应不受后续登记影响: %v", rules)
	}
	if got := s.SessionAllows(); len(got) != 4 {
		t.Fatalf("登记后清单应含 4 条: %v", got)
	}
	s.ResetSession()
	if got := s.SessionAllows(); got != nil {
		t.Fatalf("会话重置后清单应为空: %v", got)
	}
}

// TestConcurrentCheckAndSessionGrant -race 回归（AGENTS.md：许可判定链持有状态，
// 必须有 -race 回归测试兜底）：判定与会话授权并发发生。
func TestConcurrentCheckAndSessionGrant(t *testing.T) {
	s := &Service{}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				s.AllowForSession("deploy", "")
			} else {
				_ = s.Check(ctx, "deploy", nil, ModeReadOnly, Capability{AlwaysAsk: true})
			}
		}(i)
	}
	wg.Wait()
}

// TestConcurrentUpdateAndCheck -race 回归（issue #66）：宣称并发安全，则运行期
// 热更新（Update 整体换配置）与 Check/AllowForSession/SessionAllows 并发必须
// 无竞争——Check 全程持锁内快照，直接字段写只允许装配期。
func TestConcurrentUpdateAndCheck(t *testing.T) {
	s := &Service{
		ProjectRules: Ruleset{Deny: []Rule{{ToolName: "bash", Content: "rm:*"}}},
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				switch i % 4 {
				case 0:
					// 热更新：整体换新值（不原地改切片）
					s.Update(func(sv *Service) {
						sv.ProjectRules = Ruleset{Deny: []Rule{{ToolName: "bash", Content: "rm:*"}}}
						sv.DisallowedTools = map[string]bool{"reboot": true}
						sv.AllowedTools = map[string]bool{"safe_tool": true}
					})
				case 1:
					_ = s.Check(ctx, "bash", map[string]any{"command": "rm -rf /"}, ModeYolo, Capability{})
				case 2:
					_ = s.Check(ctx, "reboot", nil, ModeDefault, Capability{})
					_ = s.Check(ctx, "safe_tool", nil, ModeReadOnly, Capability{})
				case 3:
					s.AllowForSession("deploy", "")
					_ = s.SessionAllows()
				}
			}
		}(i)
	}
	wg.Wait()
	// 热更新后的配置最终可见
	if d := s.Check(ctx, "reboot", nil, ModeYolo, Capability{}); d.Behavior != Deny {
		t.Fatalf("热更新后 disallowed 应生效: %+v", d)
	}
	if d := s.Check(ctx, "safe_tool", nil, ModeReadOnly, Capability{}); d.Behavior != Allow || d.RuleID != "rule.allowedTools" {
		t.Fatalf("热更新后白名单 break-glass 应生效: %+v", d)
	}
}
