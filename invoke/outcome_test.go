package invoke

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/oekit/pkg/errors"
)

// recordOf 跑一次调用并取回留痕（门禁全放行）。
func recordOf(t *testing.T, h Handler) (Result, Record) {
	t.Helper()
	var rec Record
	c, err := NewChain(h, []Stage{allow("gate")}, WithRecorder(func(r Record) { rec = r }))
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Do(context.Background(), Call{Name: "tool"})
	if err != nil {
		return res, rec
	}
	return res, rec
}

// ── 动作层结论：执行体自拒（以成功返回结束）──

// TestOutcomeRefusalReachesRecord 是本组用例的核心断言：
// 工具在执行体内部自己拒绝了这次动作、但它是以**一次成功返回**结束的，
// 留痕里必须能看出「没动」。
//
// 缺了这条，留痕长成 Allowed=true / Err=nil，读起来是「执行了」——
// 而命令是什么只有执行体知道，门禁替它猜必然猜错方向。
func TestOutcomeRefusalReachesRecord(t *testing.T) {
	res, rec := recordOf(t, func(context.Context, Call) (Result, error) {
		return Result{
			Text:    "已拒绝：未携带 confirm",
			Outcome: &Outcome{Refused: "未携带 confirm"},
		}, nil
	})

	if rec.Outcome == nil {
		t.Fatal("动作层结论必须抄进留痕")
	}
	if rec.Outcome.Refused != "未携带 confirm" {
		t.Fatalf("拒绝原因应原样留痕，实得 %q", rec.Outcome.Refused)
	}
	if !rec.Refused() {
		t.Fatal("执行体自拒 ⇒ 留痕必须报出「被拒」")
	}
	if rec.DryRun() {
		t.Fatal("自拒不是演练")
	}
	if rec.Acted() {
		t.Fatal("执行体自拒 ⇒ 事情没做，Acted 必须为 false")
	}
	// 门禁层不受影响：执行体确实被到达了，门禁确实放行了。
	if !rec.Allowed {
		t.Fatal("执行体自拒不改变门禁层结论：调用确实到达了执行体")
	}
	if rec.Err != nil {
		t.Fatalf("自拒以成功返回结束 ⇒ 收口原因应为空，实得 %v", rec.Err)
	}
	// 返回给调用方的答复同样带着结论。
	if res.Outcome == nil || res.Outcome.Refused == "" {
		t.Fatal("返回的 Result 必须带着动作层结论")
	}
}

// TestOutcomeDryRunIsNotRefusal 钉住「演练」与「拒绝」是两个独立事实。
//
// 这条是反证样本：把 Refused / DryRun 合成一个 bool（或让演练也写 Refused），
// 本用例立刻红——因为那会让下游把演练记成拒绝，在审计唯一要回答的问题上造假警报。
func TestOutcomeDryRunIsNotRefusal(t *testing.T) {
	_, rec := recordOf(t, func(context.Context, Call) (Result, error) {
		return Result{
			Text:    "演练结果：未真正执行",
			Outcome: &Outcome{DryRun: true},
		}, nil
	})

	if rec.Outcome == nil {
		t.Fatal("动作层结论必须抄进留痕")
	}
	if !rec.DryRun() {
		t.Fatal("演练必须被留痕认出来")
	}
	if rec.Refused() {
		t.Fatal("演练不是拒绝：两个事实必须分开")
	}
	if rec.Acted() {
		t.Fatal("演练什么都没跑 ⇒ Acted 必须为 false")
	}
	if rec.Outcome.RefusalReason() != "" {
		t.Fatalf("演练不应带拒绝原因，实得 %q", rec.Outcome.RefusalReason())
	}
}

// ── 未声明 ⇒ 既有行为不变 ──

// TestOutcomeUndeclaredKeepsLegacyBehavior 钉住「未声明按执行了处理」。
//
// 这是本改动的兼容性底线：既有调用方一个都没改，它们必须看到与改动前
// 完全一样的结论——nil 不得被解读成「被拒」。
func TestOutcomeUndeclaredKeepsLegacyBehavior(t *testing.T) {
	_, rec := recordOf(t, func(context.Context, Call) (Result, error) {
		return Result{Text: "真的执行了"}, nil
	})

	if rec.Outcome != nil {
		t.Fatal("执行体未声明 ⇒ 留痕里不得凭空长出结论")
	}
	if rec.Refused() || rec.DryRun() {
		t.Fatal("未声明 ≠ 被拒 ≠ 演练")
	}
	if !rec.Acted() {
		t.Fatal("未声明且成功收口 ⇒ 按「执行了」处理")
	}
	if !rec.Allowed || rec.Err != nil {
		t.Fatalf("既有行为应不变，实得 allowed=%v err=%v", rec.Allowed, rec.Err)
	}
}

// ── error 返回路径也不丢结论 ──

// TestOutcomeSurvivesHandlerError 钉住「结论不因错误路径而丢」。
//
// 执行体若以 error 返回拒绝（而不是成功返回带结论），留痕里仍必须留着
// 「执行体说了什么」——否则这一类结局在审计面退化成「执行了」。
//
// 反证样本：把「结论抄进留痕」这一步去掉（只抄成功路径），本用例立刻红。
func TestOutcomeSurvivesHandlerError(t *testing.T) {
	_, rec := recordOf(t, func(context.Context, Call) (Result, error) {
		return Result{
				Outcome: &Outcome{Refused: "配额超限"},
			},
			errors.New("工具执行失败")
	})

	if rec.Err == nil {
		t.Fatal("执行体报错 ⇒ 收口原因必须留痕")
	}
	if rec.Outcome == nil {
		t.Fatal("错误路径也必须保留执行体声明的结论")
	}
	if rec.Outcome.Refused != "配额超限" {
		t.Fatalf("拒绝原因应原样留痕，实得 %q", rec.Outcome.Refused)
	}
	if rec.Acted() {
		t.Fatal("执行体自拒 ⇒ 事情没做，Acted 必须为 false")
	}
}

// TestRecordActedFallsBackToErrorWhenUndeclared 钉住「未声明时的兜底」。
//
// 执行体既没声明、调用又失败收口 ⇒ 按「没动」处理。
func TestRecordActedFallsBackToErrorWhenUndeclared(t *testing.T) {
	_, rec := recordOf(t, func(context.Context, Call) (Result, error) {
		return Result{}, errors.New("执行体炸了")
	})

	if rec.Outcome != nil {
		t.Fatal("执行体未声明 ⇒ 不得凭空长出结论")
	}
	if rec.Acted() {
		t.Fatal("未声明且失败收口 ⇒ 按「没动」处理")
	}
}

// ── nil 安全 ──

// TestOutcomeActedIsNilSafe 钉住「拿到指针不必先判空」。
//
// 未声明与「声明了但做了」在 Acted 上都是 true，判空只会在下游写出一份
// 漏判的分支——而漏判的方向是「把没做记成做了」。
func TestOutcomeActedIsNilSafe(t *testing.T) {
	var o *Outcome
	if !o.Acted() {
		t.Fatal("未声明的结论按「执行了」处理")
	}
	if o.RefusalReason() != "" {
		t.Fatalf("未声明时拒绝原因应为空，实得 %q", o.RefusalReason())
	}

	declared := &Outcome{}
	if !declared.Acted() {
		t.Fatal("声明了「做了」⇒ Acted 为 true")
	}
	if (&Outcome{Refused: "x"}).Acted() {
		t.Fatal("声明了「被拒」⇒ Acted 为 false")
	}
	if (&Outcome{DryRun: true}).Acted() {
		t.Fatal("声明了「演练」⇒ Acted 为 false")
	}
}

// TestRecordOutcomeSurvivesConcurrentCalls 钉住留痕在并发下不串味。
//
// 每次调用的结论必须只属于它自己那一次调用——串味一次，审计就把两次调用
// 记成同一件事。
func TestRecordOutcomeSurvivesConcurrentCalls(t *testing.T) {
	const n = 32
	var mu sync.Mutex
	recs := make([]Record, 0, n)

	c, err := NewChain(
		func(_ context.Context, call Call) (Result, error) {
			return Result{Outcome: &Outcome{Refused: call.Name}}, nil
		},
		[]Stage{allow("gate")},
		WithRecorder(func(r Record) {
			mu.Lock()
			defer mu.Unlock()
			recs = append(recs, r)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// 每次调用的工具名唯一 ⇒ 留痕里的结论必须与它自己的那次调用对上。
			_, _ = c.Do(context.Background(), Call{Name: fmt.Sprintf("tool-%d", i)})
		}(i)
	}
	wg.Wait()

	if len(recs) != n {
		t.Fatalf("每次调用恰好一条留痕，实得 %d 条（期望 %d）", len(recs), n)
	}
	for _, r := range recs {
		if r.Outcome == nil {
			t.Fatalf("留痕 %s 缺动作层结论", r.Call.Name)
		}
		if r.Outcome.Refused != r.Call.Name {
			t.Fatalf("留痕串味：%s 的结论是 %q", r.Call.Name, r.Outcome.Refused)
		}
	}
}

// ── 第三格：演练若真跑会不会跑 ──

// TestOutcomeWouldExecuteReachesRecord 钉住第三格进得了留痕通路。
//
// 这一格在下游不是冗余：演练的答复里同时带着「被风险分类挡住了」的提示，
// 而留痕**故意不把演练记成拒绝**（那是假警报）⇒ 「这次演练差一次确认」
// 这件事，在留痕里只剩这一格能说。留痕通路带不到它，下游就只能在链外
// 另开一条（一份数据两处存放）。
func TestOutcomeWouldExecuteReachesRecord(t *testing.T) {
	_, rec := recordOf(t, func(context.Context, Call) (Result, error) {
		return Result{
			Text:    "演练：未真正执行",
			Outcome: &Outcome{DryRun: true, WouldExecute: true},
		}, nil
	})

	if rec.Outcome == nil {
		t.Fatal("动作层结论必须抄进留痕")
	}
	if !rec.Outcome.WouldExecute {
		t.Fatal("第三格必须原样进留痕")
	}
	if !rec.DryRun() {
		t.Fatal("演练标记必须同时在位")
	}
}

// TestOutcomeWouldExecuteDistinguishesDryRuns 钉住「两种演练」分得开。
//
// 只记 DryRun 的话，审计答不出「这次差一步就动真格吗」——而这两个演练
// 的处置完全不同：一个是预演，一个是被挡在门外。
func TestOutcomeWouldExecuteDistinguishesDryRuns(t *testing.T) {
	_, wouldRun := recordOf(t, func(context.Context, Call) (Result, error) {
		return Result{Outcome: &Outcome{DryRun: true, WouldExecute: true}}, nil
	})
	_, blocked := recordOf(t, func(context.Context, Call) (Result, error) {
		return Result{Outcome: &Outcome{DryRun: true, WouldExecute: false}}, nil
	})

	if wouldRun.Outcome == nil || blocked.Outcome == nil {
		t.Fatal("两次调用都必须有结论")
	}
	if !wouldRun.Outcome.WouldExecute {
		t.Fatal("「本来就能跑」的演练必须带 WouldExecute=true")
	}
	if blocked.Outcome.WouldExecute {
		t.Fatal("「差一次确认」的演练必须带 WouldExecute=false")
	}
	// 两者都是演练 ⇒ 都不是拒绝（假警报要防住）
	if wouldRun.Refused() || blocked.Refused() {
		t.Fatal("演练不得被记成拒绝")
	}
}

// TestOutcomeWouldExecuteDoesNotChangeActed 钉住判定表不受第三格影响。
//
// WouldExecute 是「若真跑会怎样」的**预判**，不是「这次做了什么」的结论。
// 演练即便 WouldExecute=true，这次也什么都没做 ⇒ Acted() 仍为 false。
//
// 反证样本：把 Acted() 改成「WouldExecute 为真就当做了」⇒ 本用例立刻红。
func TestOutcomeWouldExecuteDoesNotChangeActed(t *testing.T) {
	o := &Outcome{DryRun: true, WouldExecute: true}
	if o.Acted() {
		t.Fatal("演练什么都没做，Acted 必须为 false（与 WouldExecute 无关）")
	}
	rec := Record{Outcome: o}
	if rec.Acted() {
		t.Fatal("留痕侧同理：演练没动手")
	}
}

// TestOutcomeWouldExecuteDefaultsFalseWhenNotDryRun 钉住零值语义。
//
// 不是演练时恒为 false（语义边界）⇒ 零值即可，不额外约束执行体。
func TestOutcomeWouldExecuteDefaultsFalseWhenNotDryRun(t *testing.T) {
	o := &Outcome{}
	if o.WouldExecute {
		t.Fatal("不是演练时 WouldExecute 必须为 false")
	}
	if !o.Acted() {
		t.Fatal("未声明拒绝也未演练 ⇒ Acted 为 true")
	}
}
