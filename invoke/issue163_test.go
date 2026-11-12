package invoke

// 本文件钉 guardx#163 的回归：typed-nil 环节（接口包着 nil 指针）不得逃逸
// panic 打死编排进程。stageName 此前只挡 nil interface——`var p *MyStage;
// stages = append(stages, p)` 是 Go 里极常见的接线写法，值接收者方法解引用
// nil 指针的 panic 发生在 runStage 的 recover 之外、Chain.Do 又无顶层
// recover ⇒ 进程猝死，且留痕被伪造成「未放行、无错误、无环节记录」，
// 与一次正常的门禁拒绝完全无法区分（违 doc.go 的双重承诺）。

import (
	"context"
	"errors"
	"testing"
)

// issue163TypedNil 自定义环节：值接收者方法（Name/Check 挂在 myStage 上），
// 接口装 nil 指针时取名/判定都要解引用 nil——正是探针 B3/B4 的形态。
type issue163TypedNil struct{}

func (issue163TypedNil) Name() string { return "boom" }

func (issue163TypedNil) Check(context.Context, Call) (Verdict, error) {
	return Verdict{Allow: true}, nil
}

// TestTypedNilStageFailsClosedInsteadOfCrash typed-nil 环节：被兜住转成
// *DenyError（Stage=internal），进程存活；nil interface 对照面不回归。
func TestTypedNilStageFailsClosedInsteadOfCrash(t *testing.T) {
	// 实验组：包自带 *StageFunc 的 typed-nil。
	var sf *StageFunc
	// 对照组：nil interface（既有已修面，不得回归）。
	cases := []struct {
		name   string
		stages []Stage
	}{
		{"nil interface", []Stage{nil}},
		{"*StageFunc typed-nil", []Stage{sf}},
		{"自定义 *T typed-nil", []Stage{(*issue163TypedNil)(nil)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := EvaluateStages(context.Background(), tc.stages, Call{Name: "t"})
			if err == nil {
				t.Fatal("装配漏环应拒绝（fail-closed）")
			}
			if !errors.Is(err, ErrStageFailed) {
				t.Fatalf("装配故障应归口 ErrStageFailed，实得 %v", err)
			}
			var de *DenyError
			if !errors.As(err, &de) || de.Stage != stageInternal {
				t.Fatalf("应归口到 internal，实得 %v", err)
			}
			if de.Cause == nil {
				t.Fatal("Cause 不得为空：为空等于把装配故障谎报成正常拒绝")
			}
		})
	}
}

// TestTypedNilStageRecordCarriesErr typed-nil 下的留痕必须带 Err——
// 「崩了」不得被记成「未放行、无错误」的正常门禁拒绝（探针 B4 的失真面）。
func TestTypedNilStageRecordCarriesErr(t *testing.T) {
	var rec Record
	var sf *StageFunc
	c, err := NewChain(
		func(context.Context, Call) (Result, error) { return Result{Text: "x"}, nil },
		[]Stage{sf},
		WithRecorder(func(r Record) { rec = r }),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, doErr := c.Do(context.Background(), Call{Name: "t"}); doErr == nil {
		t.Fatal("typed-nil 环节应拒绝")
	}
	if rec.Err == nil {
		t.Fatal("留痕 Err 不得为 nil：无错误的未放行会把「崩了」伪装成「被拒了」")
	}
	if rec.Allowed {
		t.Fatal("未到达执行体不该记 Allowed")
	}
	if len(rec.Stages) == 0 {
		t.Fatal("留痕应带环节记录（取名兜底后仍能说出是哪一环）")
	}
}

// TestStagesReadonlySurvivesTypedNil Chain.Stages 只读出口在 typed-nil 下
// 不得 panic——它是调试与自检路径，调用方没有理由预期它会打死进程。
func TestStagesReadonlySurvivesTypedNil(t *testing.T) {
	var sf *StageFunc
	c, err := NewChain(
		func(context.Context, Call) (Result, error) { return Result{}, nil },
		[]Stage{nil, sf, (*issue163TypedNil)(nil), StageFunc{StageName: "gate", Fn: func(context.Context, Call) (Verdict, error) { return Verdict{Allow: true}, nil }}},
	)
	if err != nil {
		t.Fatal(err)
	}
	names := c.Stages() // panic 逃逸则本用例直接失败
	want := []string{stageNil, stageNil, stageNil, "gate"}
	if len(names) != len(want) {
		t.Fatalf("环节名个数应为 %d，实得 %v", len(want), names)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("第 %d 个环节名应为 %q，实得 %q（全量 %v）", i, want[i], names[i], names)
		}
	}
}

// TestNilInterfaceNoRegression nil interface 对照面钉死：仍是 *DenyError、
// Stage=internal、归口 ErrStageFailed（#163 修复不得把这条既有语义改坏）。
func TestNilInterfaceNoRegression(t *testing.T) {
	c, err := NewChain(
		func(context.Context, Call) (Result, error) { return Result{}, nil },
		[]Stage{nil},
	)
	if err != nil {
		t.Fatal(err)
	}
	_, doErr := c.Do(context.Background(), Call{Name: "t"})
	if doErr == nil {
		t.Fatal("nil 环应拒绝")
	}
	if !errors.Is(doErr, ErrStageFailed) {
		t.Fatalf("应归口 ErrStageFailed，实得 %v", doErr)
	}
	var de *DenyError
	if !errors.As(doErr, &de) || de.Stage != stageInternal {
		t.Fatalf("应归口到 internal，实得 %v", doErr)
	}
}
