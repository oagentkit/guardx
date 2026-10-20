package toolfail

import (
	stderrors "errors"
	"strings"
	"testing"
	"time"

	"github.com/oekit/pkg/errors"
)

// contractCase 契约用例：类别 → 策略表的期望值。
//
// 这张表是**判据单源**：策略表改了而这张表没改，契约测试必须红。
// 反过来这张表改了而策略表没改，同样红——两头都锁住，才叫「单一真相」。
type contractCase struct {
	class          Class
	retryable      bool
	backoff        bool
	surfaceDelay   bool
	needsOperator  bool
	safeToResubmit bool
}

var contractCases = []contractCase{
	{ClassTransient, true, true, false, false, false},
	{ClassPermanent, false, false, false, false, false},
	{ClassAuthentication, false, false, false, true, false},
	{ClassNotFound, false, false, false, false, false},
	{ClassPermissionDenied, false, false, false, true, false},
	{ClassInvalidArgument, false, false, false, false, false},
	{ClassRateLimited, true, true, true, false, true},
	{ClassSelfReported, true, true, false, false, false},
	{ClassUnknown, false, false, false, false, false},
}

// TestPolicyTableContract 钉住策略表的每一格。
func TestPolicyTableContract(t *testing.T) {
	for _, c := range contractCases {
		p := PolicyOf(c.class)
		if p.Class != c.class {
			t.Errorf("%s: 策略的 Class 字段=%s，应为 %s", c.class, p.Class, c.class)
		}
		if p.Retryable != c.retryable {
			t.Errorf("%s: Retryable=%v，应为 %v", c.class, p.Retryable, c.retryable)
		}
		if p.Backoff != c.backoff {
			t.Errorf("%s: Backoff=%v，应为 %v", c.class, p.Backoff, c.backoff)
		}
		if p.SurfaceDelay != c.surfaceDelay {
			t.Errorf("%s: SurfaceDelay=%v，应为 %v", c.class, p.SurfaceDelay, c.surfaceDelay)
		}
		if p.NeedsOperator != c.needsOperator {
			t.Errorf("%s: NeedsOperator=%v，应为 %v", c.class, p.NeedsOperator, c.needsOperator)
		}
		if p.SafeToResubmit != c.safeToResubmit {
			t.Errorf("%s: SafeToResubmit=%v，应为 %v", c.class, p.SafeToResubmit, c.safeToResubmit)
		}
	}
}

// TestAllClassesCovered 每个类别都必须在契约表里——新增类别漏登记即红。
func TestAllClassesCovered(t *testing.T) {
	inContract := map[Class]bool{}
	for _, c := range contractCases {
		inContract[c.class] = true
	}
	for _, c := range AllClasses() {
		if !inContract[c] {
			t.Errorf("类别 %s 未登记进契约表", c)
		}
		if _, ok := policyTable[c]; !ok {
			t.Errorf("类别 %s 未登记进策略表", c)
		}
	}
}

// TestUnknownClassIsConservative 未知类别按 ClassUnknown 处理（不可重试）。
func TestUnknownClassIsConservative(t *testing.T) {
	p := PolicyOf(Class("no_such_class"))
	if p.Retryable {
		t.Error("未知类别不应可重试")
	}
	if p.Class != ClassUnknown {
		t.Errorf("未知类别应落到 ClassUnknown，实得 %s", p.Class)
	}
}

// TestRemediationCarriesNoRetryVerdict 处置指引不得自带重试结论。
//
// 它与 Guidance 的机械判定会矛盾：同一段提示词里两个相反的指令，模型无从取舍。
func TestRemediationCarriesNoRetryVerdict(t *testing.T) {
	forbidden := []string{"重试", "等待", "需要人工", "retry"}
	for _, c := range AllClasses() {
		r := PolicyOf(c).Remediation
		if r == "" {
			t.Errorf("%s: Remediation 不应为空（分类建好却没有指引等于没建）", c)
		}
		for _, w := range forbidden {
			if strings.Contains(r, w) {
				t.Errorf("%s: Remediation %q 含重试类结论 %q——该结论由 Guidance 机械判定", c, r, w)
			}
		}
	}
}

// TestClassifySentinels 哨兵路径。
func TestClassifySentinels(t *testing.T) {
	cases := []struct {
		err  error
		want Class
	}{
		{ErrTransient, ClassTransient},
		{ErrPermanent, ClassPermanent},
		{ErrAuthentication, ClassAuthentication},
		{ErrNotFound, ClassNotFound},
		{ErrPermissionDenied, ClassPermissionDenied},
		{ErrInvalidArgument, ClassInvalidArgument},
		{ErrRateLimited, ClassRateLimited},
	}
	for _, c := range cases {
		if got := Classify(c.err); got != c.want {
			t.Errorf("Classify(%v)=%s，应为 %s", c.err, got, c.want)
		}
	}
}

// TestClassifyNilAndUnknown 判不出来就是 unknown（且不可重试）。
func TestClassifyNilAndUnknown(t *testing.T) {
	if got := Classify(nil); got != ClassUnknown {
		t.Errorf("Classify(nil)=%s，应为 unknown", got)
	}
	if got := Classify(stderrors.New("随便一个错误")); got != ClassUnknown {
		t.Errorf("Classify(未知错误)=%s，应为 unknown", got)
	}
	if Retryable(stderrors.New("随便一个错误")) {
		t.Error("未知错误不应可重试")
	}
}

// TestClassifyWrappedSentinel 哨兵被 %w 包住后仍应被认出。
//
// 真实链路几乎都会包一层上下文——认不出就等于这道判据对真实链路失效。
func TestClassifyWrappedSentinel(t *testing.T) {
	wrapped := errors.Wrap(ErrRateLimited, "调用工具失败")
	if got := Classify(wrapped); got != ClassRateLimited {
		t.Errorf("Classify(包装后的哨兵)=%s，应为 rate_limited", got)
	}
}

// TestClassifyExplicitFailure 显式分类优先（最具体的一份判定）。
func TestClassifyExplicitFailure(t *testing.T) {
	f := New(ClassPermissionDenied, "acl", "没有权限")
	if got := Classify(f); got != ClassPermissionDenied {
		t.Errorf("Classify(*Failure)=%s，应为 permission_denied", got)
	}
}

// TestClassifyAs 显式归类后整条链路可被捡走。
func TestClassifyAs(t *testing.T) {
	f := ClassifyAs(ClassInvalidArgument, stderrors.New("参数缺字段"))
	if f == nil {
		t.Fatal("ClassifyAs 应返回非 nil")
	}
	if f.Class != ClassInvalidArgument {
		t.Errorf("类别=%s，应为 invalid_argument", f.Class)
	}
	wrapped := errors.Wrap(f, "外层上下文")
	got, ok := As(wrapped)
	if !ok || got == nil {
		t.Fatal("包装后应能取出 *Failure")
	}
	if got.Class != ClassInvalidArgument {
		t.Errorf("包装后类别=%s，应为 invalid_argument", got.Class)
	}
}

// TestClassifyAsNilReturnsNil ClassifyAs(nil) 不该造出一个假的失败。
func TestClassifyAsNilReturnsNil(t *testing.T) {
	if f := ClassifyAs(ClassTransient, nil); f != nil {
		t.Error("ClassifyAs(nil) 应返回 nil")
	}
}

// selfReportedErr 自报可重试的错误。
type selfReportedErr struct {
	retryable bool
}

func (e *selfReportedErr) Error() string   { return "自报错误" }
func (e *selfReportedErr) Retryable() bool { return e.retryable }

// TestClassifySelfReported 自报路径：可重试→self_reported，不可重试→unknown。
func TestClassifySelfReported(t *testing.T) {
	if got := Classify(&selfReportedErr{retryable: true}); got != ClassSelfReported {
		t.Errorf("自报可重试→%s，应为 self_reported", got)
	}
	if got := Classify(&selfReportedErr{retryable: false}); got != ClassUnknown {
		t.Errorf("自报不可重试→%s，应为 unknown", got)
	}
}

// TestClassifySelfReportedBeatsSentinel 自报优先于哨兵（自报是这次的实情）。
func TestClassifySelfReportedBeatsSentinel(t *testing.T) {
	// 自报不可重试，且错误链上挂着可重试哨兵——自报不得被哨兵翻案。
	wrapped := errors.Wrap(&selfReportedErr{retryable: false}, "层")
	if got := Classify(wrapped); got != ClassUnknown {
		t.Errorf("自报不可重试应落到 unknown，实得 %s", got)
	}
}

// TestClassifySelfReportedWrapped 自报被包住后仍能认出。
func TestClassifySelfReportedWrapped(t *testing.T) {
	wrapped := errors.Wrap(&selfReportedErr{retryable: true}, "层")
	if got := Classify(wrapped); got != ClassSelfReported {
		t.Errorf("包装后的自报→%s，应为 self_reported", got)
	}
}

// TestSafeToResubmitIsOrthogonal 重发安全与重试价值是两件事。
func TestSafeToResubmitIsOrthogonal(t *testing.T) {
	// 超时类：值得重试，但不知道上次是否已生效 → 默认不给出重发安全。
	f := New(ClassTransient, "", "超时")
	if !f.Retryable() {
		t.Error("transient 应可重试")
	}
	if f.SafeToResubmit() {
		t.Error("transient 默认不应断言重发安全（超时可能是服务端已执行）")
	}
	// 限流类：请求没进业务逻辑 → 可断言重发安全。
	f2 := New(ClassRateLimited, "", "限流")
	if !f2.SafeToResubmit() {
		t.Error("rate_limited 应可断言重发安全")
	}
}

// TestIdempotencyOverridesClassDefault 宿主逐次表态覆盖类别缺省。
func TestIdempotencyOverridesClassDefault(t *testing.T) {
	// transient 缺省不可重发；宿主明确表态幂等 → 可重发。
	f := New(ClassTransient, "", "超时")
	if f.SafeToResubmit() {
		t.Fatal("前置条件不成立：transient 缺省不应可重发")
	}
	f = f.Idempotent()
	if !f.SafeToResubmit() {
		t.Error("宿主表态幂等后应可重发")
	}
	// 限流缺省可重发；宿主明确表态有副作用 → 不可重发。
	f2 := New(ClassRateLimited, "", "限流").WithIdempotency(IdempotencyNo)
	if f2.SafeToResubmit() {
		t.Error("宿主表态有副作用后不应可重发")
	}
}

// TestIdempotencyUnsetUsesClassDefault 未表态时取类别缺省。
func TestIdempotencyUnsetUsesClassDefault(t *testing.T) {
	f := New(ClassRateLimited, "", "限流")
	if f.Idempotency != IdempotencyUnset {
		t.Error("默认应为未表态")
	}
	if !f.SafeToResubmit() {
		t.Error("未表态时应取类别缺省（rate_limited 可重发）")
	}
}

// TestIdempotencyString 机读名。
func TestIdempotencyString(t *testing.T) {
	cases := map[Idempotency]string{
		IdempotencyUnset: "unspecified",
		IdempotencyYes:   "idempotent",
		IdempotencyNo:    "side_effecting",
	}
	for i, want := range cases {
		if got := i.String(); got != want {
			t.Errorf("Idempotency(%d)=%s，应为 %s", i, got, want)
		}
	}
}

// TestGuidance 三维结论渲染。
func TestGuidance(t *testing.T) {
	// 可重试且可重发。
	g := New(ClassRateLimited, "", "限流").Guidance()
	if !strings.Contains(g, "可以直接重试") {
		t.Errorf("限流指引应说可以直接重试，实得 %q", g)
	}
	// 可重试但不可重发：必须说清「先确认上一次是否生效」。
	g = New(ClassTransient, "", "超时").Guidance()
	if !strings.Contains(g, "先确认上一次调用是否已经生效") {
		t.Errorf("超时指引必须提示确认上一次是否生效，实得 %q", g)
	}
	if strings.Contains(g, "可以直接重试") {
		t.Errorf("超时指引不应说可以直接重试，实得 %q", g)
	}
	// 不可重试。
	g = New(ClassPermanent, "", "不支持").Guidance()
	if !strings.Contains(g, "不要重试") {
		t.Errorf("永久失败指引应说不要重试，实得 %q", g)
	}
}

// TestGuidanceSurfaceDelay 限流类才暴露等待时长。
func TestGuidanceSurfaceDelay(t *testing.T) {
	f := New(ClassRateLimited, "", "限流").WithRetryAfter(3 * time.Second)
	g := f.Guidance()
	if !strings.Contains(g, "建议等待 3 秒") {
		t.Errorf("限流指引应给出等待秒数，实得 %q", g)
	}
	// 非限流类即便带 RetryAfter 也不暴露（该信息对它无意义）。
	f2 := New(ClassTransient, "", "超时").WithRetryAfter(3 * time.Second)
	if strings.Contains(f2.Guidance(), "建议等待") {
		t.Errorf("transient 不应暴露等待时长，实得 %q", f2.Guidance())
	}
}

// TestGuidanceNeedsOperator 需要人工的类别必须说出来。
func TestGuidanceNeedsOperator(t *testing.T) {
	for _, c := range []Class{ClassAuthentication, ClassPermissionDenied} {
		g := New(c, "", "x").Guidance()
		if !strings.Contains(g, "需要人工介入") {
			t.Errorf("%s 指引应说明需要人工介入，实得 %q", c, g)
		}
	}
}

// TestRemediationOverride 逐次覆盖优先于类别缺省。
func TestRemediationOverride(t *testing.T) {
	f := New(ClassInvalidArgument, "", "x").WithRemediation("把 count 参数改成正整数。")
	if got := f.Remediation(); got != "把 count 参数改成正整数。" {
		t.Errorf("逐次覆盖未生效，实得 %q", got)
	}
}

// TestNilFailureSafe nil 接收者不得 panic。
func TestNilFailureSafe(t *testing.T) {
	var f *Failure
	if f.Retryable() {
		t.Error("nil 失败不应可重试")
	}
	if f.SafeToResubmit() {
		t.Error("nil 失败不应可重发")
	}
	if f.Remediation() != "" {
		t.Error("nil 失败的指引应为空")
	}
	if f.Guidance() != "" {
		t.Error("nil 失败的指引应为空")
	}
	if f.Error() != "<nil>" {
		t.Errorf("nil 失败的错误串=%q，应为 <nil>", f.Error())
	}
	if f.Unwrap() != nil {
		t.Error("nil 失败的根因应为 nil")
	}
}

// TestFailureErrorFormat 错误串带上类别、码与等待时长。
func TestFailureErrorFormat(t *testing.T) {
	f := New(ClassRateLimited, "rl", "太频繁").WithRetryAfter(2 * time.Second)
	msg := f.Error()
	for _, want := range []string{"rate_limited", "rl", "太频繁", "retry_after=2s"} {
		if !strings.Contains(msg, want) {
			t.Errorf("错误串 %q 应含 %q", msg, want)
		}
	}
}

// TestFailureUnwrap 根因链保住。
func TestFailureUnwrap(t *testing.T) {
	cause := errors.New("根因")
	f := New(ClassTransient, "", "x").WithCause(cause)
	if !errors.Is(f, cause) {
		t.Error("应能通过 errors.Is 找到根因")
	}
}

// TestNewDefaults 空类别按 unknown、码取类别值。
func TestNewDefaults(t *testing.T) {
	f := New("", "", "msg")
	if f.Class != ClassUnknown {
		t.Errorf("空类别应落 unknown，实得 %s", f.Class)
	}
	if f.Code != string(ClassUnknown) {
		t.Errorf("空码应取类别值，实得 %q", f.Code)
	}
}
