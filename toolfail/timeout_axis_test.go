package toolfail

// 超时三轴身份契约（oagentkit/guardx#222；与 llm 侧 timeout_axis_test.go 对偶，
// 两仓 CI 各自常绿——依赖方向决定两仓不能互 import，契约以「同一判据面两处
// 各钉一半」的形式成立，对照表见 matrix-tools docs/exec-semantics.md 超时三轴节）。
//
// 钉的是「模型超时 ≠ 工具超时 ≠ 用户取消」在 errors.Is / Classify 维度的区分，
// 以及**同一字面量不同值**的事故形态回归（kernel #170/#333/#355 的教训：
// 两侧各写一份 errors.New 文本相同、值不同，errors.Is 互不认领）。

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestToolTimeoutIdentity_Issue222 轴②工具超时：进 toolfail 必须带类别载体，
// 且身份链保留（errors.Is 仍能解到底层 DeadlineExceeded）、默认不可盲目重发。
func TestToolTimeoutIdentity_Issue222(t *testing.T) {
	// 工具超时的正确形态：ClassifyAs 给类别，err 链保留 ctx 身份。
	f := ClassifyAs(ClassTransient, fmt.Errorf("tool exec: %w", context.DeadlineExceeded))
	if f.Class != ClassTransient {
		t.Fatalf("工具超时必须进 ClassTransient（可重试档），实得 %q", f.Class)
	}
	// 身份链：包一层上下文后 errors.Is 仍须解到底层超时——身份在值不在文本。
	if !errors.Is(f, context.DeadlineExceeded) {
		t.Fatal("Failure 链必须保留 DeadlineExceeded 身份（Unwrap 断了就是身份丢失）")
	}
	// 与模型超时的关键区别：工具超时**可能已施加副作用**，默认不给重发安全。
	if f.SafeToResubmit() {
		t.Fatal("工具超时默认不得断言重发安全（服务端可能已执行）")
	}
	g := f.Guidance()
	if !strings.Contains(g, "先确认上一次调用是否已经生效") {
		t.Errorf("超时指引必须提示确认上一次是否生效，实得 %q", g)
	}
	if strings.Contains(g, "可以直接重试") {
		t.Errorf("超时指引不应说可以直接重试，实得 %q", g)
	}
	// 裸 DeadlineExceeded（无类别载体）→ ClassUnknown：不可分类即不可重试，
	// 保守放行比误判成可重试安全（toolfail doc 红线）。
	if got := Classify(context.DeadlineExceeded); got != ClassUnknown {
		t.Errorf("裸 DeadlineExceeded 无载体应判 ClassUnknown（不可分类即不可重试），实得 %q", got)
	}
}

// TestUserCancelNotTimeout_Issue222 轴③对照（用户取消）：取消不进超时类、
// 不是 DeadlineExceeded——「模型超时 ≠ 用户取消」在本仓判据面的半边。
func TestUserCancelNotTimeout_Issue222(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(errors.New("用户点停止"))
	err := ctx.Err() // context.Canceled（cause 语义见 context.Cause）

	if !errors.Is(err, context.Canceled) {
		t.Fatal("取消错误必须保留 Canceled 身份")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("用户取消不得被认成超时——两者 errors.Is 维度必须分开")
	}
	// 取消不进瞬时类：重试一个用户主动停掉的动作是违背意图的。
	if got := Classify(err); got == ClassTransient {
		t.Fatal("用户取消不得归入 ClassTransient（会触发违背意图的重试）")
	}
	// 正对照：带类别载体的真超时进瞬时类（同仓同判据面，两轴互不串）。
	if got := Classify(ClassifyAs(ClassTransient, context.DeadlineExceeded)); got != ClassTransient {
		t.Fatalf("带载体的真超时应归 ClassTransient，实得 %q", got)
	}
}

// TestSameTextDifferentValue_Issue222 同一字面量不同值回归：文本相同、值不同
// 的 errors.New 不许被认领（事故形态：两侧各写一份「瞬时故障」）。
func TestSameTextDifferentValue_Issue222(t *testing.T) {
	// 正对照：真哨兵认领。
	if got := Classify(ErrTransient); got != ClassTransient {
		t.Fatalf("真哨兵 ErrTransient 应归 ClassTransient，实得 %q", got)
	}
	// 反对照：文本逐字相同、值不同 ⇒ 不认领、不进类。
	forged := errors.New(ErrTransient.Error())
	if errors.Is(forged, ErrTransient) {
		t.Fatal("同字面量不同值必须不被 errors.Is 认领（值身份不是文本身份）")
	}
	if got := Classify(forged); got != ClassUnknown {
		t.Fatalf("伪造哨兵不得归类（同字面量不同值），实得 %q", got)
	}
}
