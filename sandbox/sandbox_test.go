package sandbox

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

// fakeProvider 测试用后端。
type fakeProvider struct {
	id    string
	level Level
	out   Outcome
	err   error
}

func (f *fakeProvider) ID() string   { return f.id }
func (f *fakeProvider) Level() Level { return f.level }
func (f *fakeProvider) Exec(ctx context.Context, req Request) (Outcome, error) {
	return f.out, f.err
}

// TestLevelOrdering 档位序即强弱。
func TestLevelOrdering(t *testing.T) {
	if !(LevelNone < LevelProcess && LevelProcess < LevelOS && LevelOS < LevelMachine) {
		t.Error("档位序应递增：none < process < os < machine")
	}
}

// TestAtLeast 达到或超过才算满足。
func TestAtLeast(t *testing.T) {
	if !LevelOS.AtLeast(LevelProcess) {
		t.Error("os 应满足 process 的要求")
	}
	if !LevelOS.AtLeast(LevelOS) {
		t.Error("os 应满足 os 的要求")
	}
	if LevelProcess.AtLeast(LevelOS) {
		t.Error("process 不应满足 os 的要求")
	}
}

// TestLevelZeroValueIsWeakest 未声明档位拿到的是最弱的一档。
func TestLevelZeroValueIsWeakest(t *testing.T) {
	var l Level // 零值
	if l != LevelNone {
		t.Errorf("零值应是 LevelNone，实得 %v", l)
	}
	if l.AtLeast(LevelProcess) {
		t.Error("零值档位不应满足 process 的要求")
	}
}

// TestParseLevel 档位名解析。
func TestParseLevel(t *testing.T) {
	cases := map[string]Level{
		"none":    LevelNone,
		"process": LevelProcess,
		"os":      LevelOS,
		"machine": LevelMachine,
	}
	for name, want := range cases {
		got, err := ParseLevel(name)
		if err != nil {
			t.Errorf("ParseLevel(%q) 报错: %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("ParseLevel(%q)=%v，应为 %v", name, got, want)
		}
	}
}

// TestParseLevelUnknownFailsLoudly 未知档位必须报错，不退回缺省档位。
//
// 静默退回 LevelNone 等于把「我以为很强」变成「其实没有」——这正是本包要防的落差。
func TestParseLevelUnknownFailsLoudly(t *testing.T) {
	got, err := ParseLevel("kernel")
	if err == nil {
		t.Fatal("未知档位必须报错")
	}
	if got != LevelNone {
		t.Errorf("出错时返回的档位应是 LevelNone，实得 %v", got)
	}
	if !strings.Contains(err.Error(), "kernel") {
		t.Errorf("错误信息应含出错的名字，实得 %q", err.Error())
	}
}

// TestLevelString 档位名往返。
func TestLevelString(t *testing.T) {
	cases := map[Level]string{
		LevelNone:    "none",
		LevelProcess: "process",
		LevelOS:      "os",
		LevelMachine: "machine",
	}
	for l, want := range cases {
		if got := l.String(); got != want {
			t.Errorf("Level(%d).String()=%s，应为 %s", l, got, want)
		}
	}
}

// TestLevelStringOutOfRange 越界档位不得panic。
func TestLevelStringOutOfRange(t *testing.T) {
	got := Level(99).String()
	if !strings.Contains(got, "99") {
		t.Errorf("越界档位名应含数值，实得 %q", got)
	}
}

// TestRegisterAndResolve 登记后可按档位选出。
func TestRegisterAndResolve(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(&fakeProvider{id: "p", level: LevelProcess}); err != nil {
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

// TestResolvePicksWeakestSufficient 选出**最弱**满足者（够用且最省）。
func TestResolvePicksWeakestSufficient(t *testing.T) {
	reg := NewRegistry()
	for _, f := range []*fakeProvider{
		{id: "machine", level: LevelMachine},
		{id: "os", level: LevelOS},
		{id: "process", level: LevelProcess},
	} {
		if err := reg.Register(f); err != nil {
			t.Fatalf("登记失败: %v", err)
		}
	}
	p, err := reg.Resolve(LevelProcess)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if p.ID() != "process" {
		t.Errorf("选出 %s，应为最弱满足者 process", p.ID())
	}
	// 提高要求后应选出更强的那个。
	p, err = reg.Resolve(LevelOS)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if p.ID() != "os" {
		t.Errorf("选出 %s，应为 os", p.ID())
	}
}

// TestResolveRefusesWhenNoneSatisfies 核心语义：没有满足者就拒绝，**不降级**。
//
// 降级会让「宿主声明的强度」与「实际执行的强度」之间没有信号，
// 档位整套机制就成装饰。
func TestResolveRefusesWhenNoneSatisfies(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(&fakeProvider{id: "process", level: LevelProcess}); err != nil {
		t.Fatalf("登记失败: %v", err)
	}
	p, err := reg.Resolve(LevelOS)
	if err == nil {
		t.Fatal("无满足者时必须报错")
	}
	if p != nil {
		t.Error("无满足者时不得返回后端")
	}
	if !errors.Is(err, ErrNoProvider) {
		t.Errorf("错误应可被 errors.Is(ErrNoProvider) 认出，实得 %v", err)
	}
	if !strings.Contains(err.Error(), "os") {
		t.Errorf("错误信息应含要求的档位，实得 %q", err.Error())
	}
}

// TestResolveEmptyRegistry 空登记簿同样拒绝。
func TestResolveEmptyRegistry(t *testing.T) {
	reg := NewRegistry()
	if _, err := reg.Resolve(LevelNone); !errors.Is(err, ErrNoProvider) {
		t.Errorf("空登记簿应报 ErrNoProvider，实得 %v", err)
	}
}

// TestRegisterRejectsDuplicate 重复标识即拒（装配期缺陷不留到执行期）。
func TestRegisterRejectsDuplicate(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(&fakeProvider{id: "p", level: LevelProcess}); err != nil {
		t.Fatalf("登记失败: %v", err)
	}
	err := reg.Register(&fakeProvider{id: "p", level: LevelOS})
	if err == nil {
		t.Fatal("重复标识必须被拒")
	}
	if !errors.Is(err, ErrDuplicateProvider) {
		t.Errorf("错误应可被 errors.Is(ErrDuplicateProvider) 认出，实得 %v", err)
	}
}

// TestRegisterRejectsNilAndEmptyID 空后端与空标识都不收。
func TestRegisterRejectsNilAndEmptyID(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(nil); err == nil {
		t.Error("空后端必须被拒")
	}
	if err := reg.Register(&fakeProvider{id: "", level: LevelProcess}); err == nil {
		t.Error("空标识必须被拒")
	}
}

// TestProvidersSorted 快照按档位升序、同档位按标识升序（稳定答案）。
func TestProvidersSorted(t *testing.T) {
	reg := NewRegistry()
	for _, f := range []*fakeProvider{
		{id: "b", level: LevelProcess},
		{id: "a", level: LevelProcess},
		{id: "z", level: LevelOS},
	} {
		if err := reg.Register(f); err != nil {
			t.Fatalf("登记失败: %v", err)
		}
	}
	got := reg.Providers()
	want := []string{"a", "b", "z"}
	if len(got) != len(want) {
		t.Fatalf("应有 %d 个后端，实得 %d", len(want), len(got))
	}
	for i, id := range want {
		if got[i].ID() != id {
			t.Errorf("第 %d 个应为 %s，实得 %s", i, id, got[i].ID())
		}
	}
}

// TestProvidersSnapshotIsCopy 快照是副本，改它不影响登记簿。
func TestProvidersSnapshotIsCopy(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(&fakeProvider{id: "p", level: LevelProcess}); err != nil {
		t.Fatalf("登记失败: %v", err)
	}
	snap := reg.Providers()
	snap[0] = &fakeProvider{id: "篡改", level: LevelMachine}
	if reg.Providers()[0].ID() != "p" {
		t.Error("快照不得与登记簿共享底层数组")
	}
}

// TestExecutePicksAndRuns 执行入口：选后端并执行。
func TestExecutePicksAndRuns(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(&fakeProvider{
		id: "p", level: LevelProcess,
		out: Outcome{OK: true, Value: "结果"},
	}); err != nil {
		t.Fatalf("登记失败: %v", err)
	}
	out, err := Execute(context.Background(), reg, LevelProcess, Request{Program: "x"})
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if !out.OK || out.Value != "结果" {
		t.Errorf("执行结果不对: %+v", out)
	}
}

// TestExecuteRefusesWhenNoSatisfyingProvider 执行入口不得降级。
func TestExecuteRefusesWhenNoSatisfyingProvider(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(&fakeProvider{id: "p", level: LevelProcess}); err != nil {
		t.Fatalf("登记失败: %v", err)
	}
	out, err := Execute(context.Background(), reg, LevelMachine, Request{Program: "x"})
	if err == nil {
		t.Fatal("无满足者时必须报错")
	}
	if out.OK {
		t.Error("拒绝时不得返回成功结果")
	}
	if !errors.Is(err, ErrNoProvider) {
		t.Errorf("错误应可被 errors.Is(ErrNoProvider) 认出，实得 %v", err)
	}
}

// TestRegistryConcurrent 登记簿并发安全（配合 -race）。
func TestRegistryConcurrent(t *testing.T) {
	reg := NewRegistry()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = reg.Register(&fakeProvider{id: string(rune('a' + i)), level: LevelProcess})
			_, _ = reg.Resolve(LevelProcess)
			_ = reg.Providers()
		}(i)
	}
	wg.Wait()
}

// TestFailureIsError 后端失败形状。
func TestFailureIsError(t *testing.T) {
	f := &Failure{Kind: "compile", Message: "语法错误"}
	var err error = f
	if err.Error() != "语法错误" {
		t.Errorf("错误文案=%q，应为 语法错误", err.Error())
	}
	if f.Kind != "compile" {
		t.Errorf("Kind=%q，应为 compile", f.Kind)
	}
}
