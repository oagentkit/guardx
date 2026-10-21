package sandbox

import (
	"context"
	"errors"
	"testing"
)

// —— 本文件钉的是「扩预算面 + 支持面」的三条契约 ——
//
//  1. 既有 Provider 实现**编译期零改动**、行为**逐字不变**；
//  2. 兜不住预算的后端**不被选中**（不是选中后失败）；
//  3. 支持的后端被选中，且仍取**最弱**满足者。

// capableProvider 声明支持面的后端。
type capableProvider struct {
	id    string
	level Level
	sup   func(Budget) bool
}

func (c *capableProvider) ID() string             { return c.id }
func (c *capableProvider) Level() Level           { return c.level }
func (c *capableProvider) Supports(b Budget) bool { return c.sup(b) }
func (c *capableProvider) Exec(ctx context.Context, r Request) (Outcome, error) {
	return Outcome{OK: true}, nil
}

// plainProvider 不实现 Capable 的后端（既有实现的形态）。
type plainProvider struct {
	id    string
	level Level
}

func (p *plainProvider) ID() string   { return p.id }
func (p *plainProvider) Level() Level { return p.level }
func (p *plainProvider) Exec(ctx context.Context, r Request) (Outcome, error) {
	return Outcome{OK: true}, nil
}

// TestBudgetMaxMemoryDefault 零值 = 不要求。
func TestBudgetMaxMemoryDefault(t *testing.T) {
	var b Budget
	if b.MaxMemory != 0 {
		t.Errorf("MaxMemory 零值应为 0（不要求），实得 %d", b.MaxMemory)
	}
}

// TestSupportsBasicOnlyCoversThreeGates 未实现 Capable 的后端只兑现三闸。
func TestSupportsBasicOnlyCoversThreeGates(t *testing.T) {
	// 不要求内存 → 兜得住。
	if !SupportsBasic(Budget{}) {
		t.Error("零要求应视为兜得住")
	}
	// 只要求墙钟/调用数/字节 → 兜得住（这三闸是基本项）。
	if !SupportsBasic(Budget{WallClock: 1, MaxCalls: 2, MaxBytes: 3}) {
		t.Error("只要求基本三闸时应视为兜得住")
	}
	// 要求内存 → 兜不住。
	if SupportsBasic(Budget{MaxMemory: 1 << 20}) {
		t.Error("要求内存时基本后端应报兜不住")
	}
}

// TestSupportsAll 全支持。
func TestSupportsAll(t *testing.T) {
	if !SupportsAll(Budget{MaxMemory: 1 << 20}) {
		t.Error("SupportsAll 应恒为真")
	}
}

// TestCapableFunc 适配器。
func TestCapableFunc(t *testing.T) {
	c := CapableFunc(func(b Budget) bool { return b.MaxMemory == 0 })
	if !c.Supports(Budget{}) {
		t.Error("应支持零要求")
	}
	if c.Supports(Budget{MaxMemory: 1}) {
		t.Error("应不支持内存要求")
	}
}

// TestResolveIgnoresBudgetWhenOmitted 省略预算时只看档位（既有行为逐字不变）。
//
// 这条钉的是**向后兼容**：既有调用点 `Resolve(min)` 编译通过，且选出同一个后端。
func TestResolveIgnoresBudgetWhenOmitted(t *testing.T) {
	reg := NewRegistry()
	// 一个只兑现三闸的后端——若省略预算时被预算过滤掉，这条就红了。
	if err := reg.Register(&plainProvider{id: "p", level: LevelProcess}); err != nil {
		t.Fatalf("登记失败: %v", err)
	}
	p, err := reg.Resolve(LevelProcess)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if p.ID() != "p" {
		t.Errorf("选出 %s，应为 p", p.ID())
	}
}

// TestResolveExcludesUnsupportedBudget 兜不住预算的后端不被选中。
func TestResolveExcludesUnsupportedBudget(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(&plainProvider{id: "plain", level: LevelProcess}); err != nil {
		t.Fatalf("登记失败: %v", err)
	}
	// 要求内存：plain 兜不住 ⇒ 不被选中；无其他候选 ⇒ 拒绝。
	p, err := reg.Resolve(LevelProcess, Budget{MaxMemory: 1 << 20})
	if err == nil {
		t.Fatal("无满足者时必须拒绝")
	}
	if p != nil {
		t.Error("无满足者时不得返回后端")
	}
	if !errors.Is(err, ErrNoProvider) {
		t.Errorf("错误应可被 errors.Is(ErrNoProvider) 认出，实得 %v", err)
	}
}

// TestResolvePicksCapableBackend 支持的后端被选中。
func TestResolvePicksCapableBackend(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(&plainProvider{id: "plain", level: LevelOS}); err != nil {
		t.Fatalf("登记失败: %v", err)
	}
	cap := &capableProvider{id: "cap", level: LevelProcess, sup: SupportsAll}
	if err := reg.Register(cap); err != nil {
		t.Fatalf("登记失败: %v", err)
	}
	p, err := reg.Resolve(LevelProcess, Budget{MaxMemory: 1 << 20})
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if p.ID() != "cap" {
		t.Errorf("选出 %s，应为 cap（plain 兜不住内存）", p.ID())
	}
}

// TestResolveStillPicksWeakestSufficient 预算过滤后仍取**最弱**满足者。
func TestResolveStillPicksWeakestSufficient(t *testing.T) {
	reg := NewRegistry()
	weak := &capableProvider{id: "weak", level: LevelProcess, sup: SupportsAll}
	strong := &capableProvider{id: "strong", level: LevelOS, sup: SupportsAll}
	for _, p := range []Provider{strong, weak} {
		if err := reg.Register(p); err != nil {
			t.Fatalf("登记失败: %v", err)
		}
	}
	got, err := reg.Resolve(LevelProcess, Budget{MaxMemory: 1 << 20})
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if got.ID() != "weak" {
		t.Errorf("选出 %s，应为最弱满足者 weak", got.ID())
	}
}

// TestResolveMergesBudgets 多组预算逐项取要求更高者。
func TestResolveMergesBudgets(t *testing.T) {
	merged := mergeBudgets(
		Budget{WallClock: 1, MaxCalls: 1, MaxBytes: 1, MaxMemory: 1},
		Budget{WallClock: 2, MaxCalls: 2, MaxBytes: 2, MaxMemory: 2},
	)
	want := Budget{WallClock: 2, MaxCalls: 2, MaxBytes: 2, MaxMemory: 2}
	if merged != want {
		t.Errorf("合并结果=%+v，应为 %+v", merged, want)
	}
	// 合并是**取上限**不是求和——两组各要 2 次调用，结果应是 2 而不是 4。
	if merged.MaxCalls != 2 {
		t.Errorf("MaxCalls=%d，应为 2（取上限，不是求和）", merged.MaxCalls)
	}
}

// TestExecuteRefusesUnsupportedBudget Execute 用 req.Budget 选后端。
func TestExecuteRefusesUnsupportedBudget(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(&plainProvider{id: "plain", level: LevelProcess}); err != nil {
		t.Fatalf("登记失败: %v", err)
	}
	// 请求要求内存兜底，而 plain 兜不住 ⇒ 拒绝执行（而不是执行后才发现）。
	_, err := Execute(context.Background(), reg, LevelProcess, Request{
		Program: "x",
		Budget:  Budget{MaxMemory: 1 << 20},
	})
	if err == nil {
		t.Fatal("应拒绝执行")
	}
	if !errors.Is(err, ErrNoProvider) {
		t.Errorf("错误应可被 errors.Is(ErrNoProvider) 认出，实得 %v", err)
	}
}

// TestExecuteUnchangedWithoutMemoryRequirement 既有调用逐字不变。
func TestExecuteUnchangedWithoutMemoryRequirement(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(&plainProvider{id: "plain", level: LevelProcess}); err != nil {
		t.Fatalf("登记失败: %v", err)
	}
	out, err := Execute(context.Background(), reg, LevelProcess, Request{Program: "x"})
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if !out.OK {
		t.Error("应执行成功")
	}
}
