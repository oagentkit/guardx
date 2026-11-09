package permgate

import "testing"

// 本文件钉 guardx#129 的回归：splitCommand 必须拆单个 &（POSIX shell 的后台
// 控制操作符）。此前只拆 `&&`，单个 & 落 default 分支当普通字符——不带引号时
// 真实 shell 恰恰在 & 处分命令，allow 侧「每段命中」失效（危险命令搭 allow
// 车）、deny 侧「任一段命中」失效（危险段藏过前缀规则），两个方向都 fail-open。
// 引号内（URL 常客）受 inSingle/inDouble 保护，不受影响。

// TestSplitCommandAmpersand 单个 & 拆段：与 `|` 同等对待；引号内不拆；
// && 语义不变（两个 & 各自 flush，空段丢弃）。
func TestSplitCommandAmpersand(t *testing.T) {
	cases := []struct {
		cmd  string
		want []string
	}{
		{"git status & rm -rf /", []string{"git status", "rm -rf /"}},
		{"echo done &rm -rf /", []string{"echo done", "rm -rf /"}},                   // & 后可不带空白
		{"a&&b", []string{"a", "b"}},                                                 // && 语义不变
		{"a & & b", []string{"a", "b"}},                                              // 相邻操作符空段丢弃
		{"cmd &", []string{"cmd"}},                                                   // 尾悬
		{"& cmd", []string{"cmd"}},                                                   // 前悬
		{`echo "a & b"`, []string{`echo "a & b"`}},                                   // 双引号内不拆
		{`echo 'x&y'`, []string{`echo 'x&y'`}},                                       // 单引号内不拆
		{`curl "https://x.com/?a=1&b=2"`, []string{`curl "https://x.com/?a=1&b=2"`}}, // 带引号 URL 完整
		// 不带引号的 URL 查询串：真实 shell 同样在此分命令（拆分与语义对齐）
		{"https://x.com/?a=1&b=2", []string{"https://x.com/?a=1", "b=2"}},
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

// TestAmpersandNoAllowRide issue 复现 A：`git status & rm -rf /` 不得命中
// `git status:*` 前缀 allow 搭车放行——单 & 拆段后 rm 段不在名单，allow 失配
// 落兜底 ask。
func TestAmpersandNoAllowRide(t *testing.T) {
	s := &Service{
		ProjectRules: Ruleset{Allow: []Rule{{ToolName: "bash", Content: "git status:*"}}},
	}
	if d := s.Check(ctx, "bash", "git status & rm -rf /", ModeDefault, Capability{}); d.Behavior != Ask {
		t.Fatalf("单 & 复合命令不得搭 allow 车: %+v", d)
	}
	// 全段命中仍放行（量词语义不因新操作符收紧过度）
	if d := s.Check(ctx, "bash", "git status & git status --short", ModeDefault, Capability{}); d.Behavior != Allow {
		t.Fatalf("全段命中应放行: %+v", d)
	}
	// 对照：&& 形态行为不变
	if d := s.Check(ctx, "bash", "git status && rm -rf /", ModeDefault, Capability{}); d.Behavior != Ask {
		t.Fatalf("&& 复合不得搭车（既有语义）: %+v", d)
	}
}

// TestAmpersandDenySegment issue 复现 B：deny 前缀 `rm:*` 下
// `echo done & rm -rf /` 不得借整段匹配躲进 yolo——单 & 拆段后 rm 段命中 deny。
func TestAmpersandDenySegment(t *testing.T) {
	s := &Service{
		ProjectRules: Ruleset{Deny: []Rule{{ToolName: "bash", Content: "rm:*"}}},
	}
	if d := s.Check(ctx, "bash", "echo done & rm -rf /", ModeYolo, Capability{}); d.Behavior != Deny || d.RuleID != "rule.project.deny" {
		t.Fatalf("单 & 藏危险段应拦（yolo 压不过禁）: %+v", d)
	}
	// 对照：无危险段不误拦
	if d := s.Check(ctx, "bash", "echo done & ls /tmp", ModeYolo, Capability{}); d.Behavior != Allow {
		t.Fatalf("无危险段的 & 复合不应误拦: %+v", d)
	}
}
