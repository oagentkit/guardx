package rbac

import (
	"reflect"
	"sync"
	"testing"
)

// testMatrix 宿主词表示例（词表是宿主数据——这里的词只是测试领域词汇，
// 本包对任何词表形状同等工作）。
func testMatrix() Matrix {
	return Matrix{
		"admin":  {"platform.read", "session.write", "approval.decide", "user.manage"},
		"user":   {"platform.read", "session.write", "approval.decide"},
		"viewer": {"platform.read"},
	}
}

// TestCanFailClosed 查表 fail-closed：矩阵外没有能力（未声明角色、未授予
// 能力词、nil 矩阵一律 false）；词表原样比对不归一（大小写敏感——拼写
// 纪律归宿主的词表闭合 lint 管，机制不做魔法）。
func TestCanFailClosed(t *testing.T) {
	m := testMatrix()
	for _, c := range []struct {
		role, perm string
		want       bool
	}{
		{"admin", "platform.read", true},
		{"user", "session.write", true},
		{"viewer", "session.write", false},
		{"ghost", "platform.read", false}, // 未声明角色
		{"admin", "nonexistent", false},   // 词表外能力词
		{"Admin", "platform.read", false}, // 大小写敏感：不归一
		{"user", "Platform.Read", false},  // 同上
	} {
		if got := m.Can(c.role, c.perm); got != c.want {
			t.Errorf("Can(%q, %q)=%v，应 %v", c.role, c.perm, got, c.want)
		}
	}
	var nilMatrix Matrix
	if nilMatrix.Can("admin", "platform.read") {
		t.Error("nil 矩阵必须恒 false（fail-closed）")
	}
}

// TestReadOnlyDerived 只读档由矩阵推导，不硬编码角色名：判据恒为「能力集
// 不含写面能力」。矩阵改了（viewer 之外新增只读角色、或给某角色收回写面
// 词），推导自动跟随——这就是硬编码 role=="viewer" 防不住的漂移。
func TestReadOnlyDerived(t *testing.T) {
	m := testMatrix()
	writeFace := map[string]bool{"session.write": true, "user.manage": true}
	for _, c := range []struct {
		role string
		want bool
	}{
		{"viewer", true}, // 能力集无写面 → 只读
		{"user", false},  // 有 session.write → 非只读
		{"admin", false}, // 有写面 → 非只读
		{"ghost", true},  // 矩阵外角色：能力集为空 = 无写面 = 只读档（保守侧）
	} {
		if got := m.ReadOnly(c.role, writeFace); got != c.want {
			t.Errorf("ReadOnly(%q)=%v，应 %v", c.role, got, c.want)
		}
	}
	// 推导跟随矩阵演进：给 viewer 加写面词 → 立刻非只读（硬编码做不到）。
	m["viewer"] = []string{"platform.read", "session.write"}
	if m.ReadOnly("viewer", writeFace) {
		t.Error("矩阵演进后只读档推导必须跟随")
	}
}

// TestReadOnlyFailClosed 写面词表 nil/空 = 无法证明任何能力是读面 = 全角色
// 推导为只读（写面全禁）——漏声明得到的是「全禁」，不是「全放」。
func TestReadOnlyFailClosed(t *testing.T) {
	m := testMatrix()
	for _, wf := range []map[string]bool{nil, {}} {
		for _, role := range []string{"admin", "user", "viewer", "ghost"} {
			if !m.ReadOnly(role, wf) {
				t.Errorf("写面词表未声明（%v）时 ReadOnly(%q) 必须为 true（fail-closed：全禁方向）", wf, role)
			}
		}
	}
}

// TestSnapshot 授权面指纹：确定性（同矩阵恒同串）、去重、字典序、任何增删
// 改都改变指纹；nil 矩阵 = 空串。
func TestSnapshot(t *testing.T) {
	m := testMatrix()
	m["user"] = append(m["user"], "platform.read") // 重复词无语义
	want := "admin=approval.decide,platform.read,session.write,user.manage\n" +
		"user=approval.decide,platform.read,session.write\n" +
		"viewer=platform.read\n"
	if got := m.Snapshot(); got != want {
		t.Fatalf("指纹不符:\n got=%q\nwant=%q", got, want)
	}
	again := testMatrix()
	again["user"] = append(again["user"], "platform.read")
	if again.Snapshot() != m.Snapshot() {
		t.Error("同矩阵必须恒同指纹（确定性）")
	}
	// 声明的任何增删改都改变指纹。
	fingerprint := func(x Matrix) string { return x.Snapshot() }
	base := fingerprint(m)
	m["viewer"] = []string{"platform.read", "session.write"}
	if fingerprint(m) == base {
		t.Error("矩阵变更必须改变指纹")
	}
	var nilMatrix Matrix
	if nilMatrix.Snapshot() != "" {
		t.Error("nil 矩阵指纹应为空串")
	}
}

// TestLintUnconsumed 判据一（矩阵不得装饰化）：消费点回调未注入 = 无法核实
// = 每条能力词报疑点（fail-loud，判据的死法是沉默）；回调否决的词逐条报，
// 通过的词不报。
func TestLintUnconsumed(t *testing.T) {
	m := testMatrix()
	// 回调未注入：全部能力词（去重后 4 条）逐词报。
	findings := m.Lint(LintOptions{})
	var got []string
	for _, f := range findings {
		if f.Kind != FindingUnconsumedPerm {
			t.Fatalf("回调未注入只应产出 %s，实得 %s", FindingUnconsumedPerm, f.Kind)
		}
		got = append(got, f.Perm)
	}
	if want := []string{"approval.decide", "platform.read", "session.write", "user.manage"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("未注入回调应逐词报疑点: %v", got)
	}
	// 回调注入：只报宿主否决的词。
	seen := map[string]int{}
	findings = m.Lint(LintOptions{ConsumedBy: func(perm string) bool {
		seen[perm]++
		return perm != "user.manage" && perm != "approval.decide"
	}})
	if len(findings) != 2 {
		t.Fatalf("应只报 2 条无消费点能力词，实得 %v", findings)
	}
	for _, f := range findings {
		if f.Kind != FindingUnconsumedPerm || (f.Perm != "user.manage" && f.Perm != "approval.decide") {
			t.Errorf("疑点不符: %+v", f)
		}
		if f.Role == "" {
			t.Errorf("FindingUnconsumedPerm 应带首个授予角色作定位线索: %+v", f)
		}
	}
	// 回调被逐词调用（去重后的词表，无重复调用）。
	if len(seen) != 4 {
		t.Errorf("回调应恰好覆盖 4 条去重能力词: %v", seen)
	}
}

// TestLintRoleClosure 判据二（角色词表闭合）：矩阵角色必须都在宿主词表内；
// 词表未提供则跳过。
func TestLintRoleClosure(t *testing.T) {
	m := Matrix{
		"admin":    {"platform.read"},
		"viewr":    {"platform.read"}, // 拼写错造出的新角色
		"ops_team": {"platform.read"},
	}
	findings := m.Lint(LintOptions{
		ConsumedBy: func(string) bool { return true },
		Roles:      []string{"admin", "ops_team", "user", "viewer"},
	})
	if len(findings) != 1 || findings[0].Kind != FindingUnknownRole || findings[0].Role != "viewr" {
		t.Fatalf("应只报 viewr 的词表闭合破坏，实得 %+v", findings)
	}
	if len(m.Lint(LintOptions{ConsumedBy: func(string) bool { return true }})) != 0 {
		t.Error("词表未提供时闭合判据应跳过")
	}
}

// TestLintMonotonic 判据三（矩阵单调）：相邻两层高层 ⊇ 低层，传递性覆盖全链；
// 层级未提供则跳过；层级声明而矩阵未列的角色按空能力集参与核对。
func TestLintMonotonic(t *testing.T) {
	m := testMatrix()
	m["viewer"] = []string{"platform.read", "audit.read"} // 低层持有高层没有的能力词
	findings := m.Lint(LintOptions{
		ConsumedBy: func(string) bool { return true },
		Order:      []string{"admin", "user", "viewer"},
	})
	if len(findings) != 1 {
		t.Fatalf("应只报 user←viewer 一处单调破坏，实得 %+v", findings)
	}
	f := findings[0]
	if f.Kind != FindingNonMonotonic || f.Role != "user" || f.Perm != "audit.read" {
		t.Fatalf("单调破坏疑点不符: %+v", f)
	}
	// 层级里声明而矩阵未列的角色按空能力集核对：superadmin 缺位 = 缺低层
	// 全部能力（viewer 在前一步被改成 platform.read + audit.read 两条）。
	findings = m.Lint(LintOptions{
		ConsumedBy: func(string) bool { return true },
		Order:      []string{"superadmin", "viewer"},
	})
	if len(findings) != 2 || findings[0].Role != "superadmin" || findings[0].Perm != "audit.read" || findings[1].Perm != "platform.read" {
		t.Fatalf("缺位高层应按空能力集核对，实得 %+v", findings)
	}
	if len(m.Lint(LintOptions{ConsumedBy: func(string) bool { return true }})) != 0 {
		t.Error("层级未提供时单调判据应跳过")
	}
}

// TestLintClean 全判据通过 = nil（无疑点）。
func TestLintClean(t *testing.T) {
	findings := testMatrix().Lint(LintOptions{
		ConsumedBy: func(string) bool { return true },
		Roles:      []string{"admin", "user", "viewer", "guest"},
		Order:      []string{"admin", "user", "viewer"},
	})
	if findings != nil {
		t.Fatalf("干净矩阵应无疑点，实得 %+v", findings)
	}
}

// TestMatrixMethodsConcurrent 并发契约：方法只读入参、无共享可变状态——
// -race 下并发查表/推导/指纹/lint 无竞争。
func TestMatrixMethodsConcurrent(t *testing.T) {
	m := testMatrix()
	writeFace := map[string]bool{"session.write": true}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 200 {
				_ = m.Can("admin", "platform.read")
				_ = m.ReadOnly("viewer", writeFace)
				_ = m.Snapshot()
				_ = m.Lint(LintOptions{ConsumedBy: func(string) bool { return true }, Roles: []string{"admin", "user", "viewer"}, Order: []string{"admin", "user", "viewer"}})
			}
		})
	}
	wg.Wait()
}
