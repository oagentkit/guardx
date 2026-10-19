package invoke

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/oekit/pkg/errors"
)

// errRing 一环会报错的守卫：嘴上放行、实际报错——更该拒。
func errRing(name string, cause error) Stage {
	return StageFunc{StageName: name, Fn: func(context.Context, Call) (Verdict, error) {
		return Verdict{Allow: true}, cause
	}}
}

// panicRing 一环会 panic 的守卫，panic 值为 v。
func panicRing(name string, v any) Stage {
	return StageFunc{StageName: name, Fn: func(context.Context, Call) (Verdict, error) {
		panic(v)
	}}
}

// ── 环语义只有一份：求值入口与链一致 ──

// TestEvaluateStagesAllowsWhenEveryRingPasses 全环通过放行。
func TestEvaluateStagesAllowsWhenEveryRingPasses(t *testing.T) {
	if err := EvaluateStages(context.Background(),
		[]Stage{allow("a"), allow("b")}, Call{Name: "t"}); err != nil {
		t.Fatalf("全环通过应放行，实得 %v", err)
	}
}

// TestEvaluateStagesWithoutRingsAllows 非空名 + 无环 = 放行。
//
// 这条是给「程序内调用」那条路径兜底的：它过去有一句 `len(stages)==0 就直接放行`，
// 而链没有这句。宿主没装配任何环时，两条路径必须给出同一个答案。
func TestEvaluateStagesWithoutRingsAllows(t *testing.T) {
	if err := EvaluateStages(context.Background(), nil, Call{Name: "t"}); err != nil {
		t.Fatalf("未装配环不应拦非空名，实得 %v", err)
	}
}

// TestEvaluateStagesDeniesCarriesRingerAndRetryable 拒绝要能回答「哪一环拒的、
// 为什么、值不值得重试」，调用方不该靠比对文本。
func TestEvaluateStagesDeniesCarriesRingerAndRetryable(t *testing.T) {
	err := EvaluateStages(context.Background(),
		[]Stage{allow("first"), deny("policy", true)}, Call{Name: "t", Caller: "agent"})
	if err == nil {
		t.Fatal("应被拒")
	}
	var de *DenyError
	if !errors.As(err, &de) {
		t.Fatalf("应回 DenyError，实得 %T", err)
	}
	if de.Stage != "policy" {
		t.Fatalf("应指出是哪一环拒的，实得 %q", de.Stage)
	}
	if de.Tool != "t" || de.Reason != "策略不允许" || !de.Retryable {
		t.Fatalf("拒绝信息不完整：%+v", de)
	}
	// 正常判定得出的拒绝，「这环自己坏了」必须判否——否则调用方会去修守卫代码。
	if errors.Is(err, ErrStageFailed) {
		t.Fatal("正常拒绝不该被归口成 ErrStageFailed")
	}
	if de.Cause != nil {
		t.Fatalf("正常拒绝的 Cause 应为空（文档就是这么定义的），实得 %v", de.Cause)
	}
}

// TestEvaluateStagesAttributesRingFailureToInternal 是本文件最要紧的一条。
//
// 环**自己出问题**（返回 error 或 panic）必须与「环正常拒绝」可区分：
//   - errors.Is(err, ErrStageFailed) 为真；
//   - DenyError.Stage 是包内的 stageInternal，不是守卫自己的名字；
//   - Cause 非 nil，调用方能顺着它挖到根因。
//
// 这三项在下游复制的那份环里丢了两项，于是经那条路径触发的守卫 panic
// 被谎报成「守卫正常拒绝了」：调用方拿着错误去修策略，而真正该修的是守卫代码。
// 归口用的 stageInternal 是包内未导出常量，下游补不了，只能在这里保证。
func TestEvaluateStagesAttributesRingFailureToInternal(t *testing.T) {
	boom := errors.New("判定源不可用")

	cases := []struct {
		name       string
		ring       Stage
		wantCause  error  // 期望能被 errors.Is 命中的原始错误
		wantInText string // 期望出现在 Reason 里的原文
	}{
		{"环报错", errRing("flaky", boom), boom, "判定源不可用"},
		{"环 panic 抛 error 值", panicRing("crasher", boom), boom, "判定源不可用"},
		{"环 panic 抛裸字符串", panicRing("crasher", "环里炸了"), nil, "环里炸了"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := EvaluateStages(context.Background(), []Stage{tc.ring}, Call{Name: "t"})
			if err == nil {
				t.Fatal("环自身出问题应拒绝")
			}
			var de *DenyError
			if !errors.As(err, &de) {
				t.Fatalf("应回 DenyError，实得 %T", err)
			}
			if !errors.Is(err, ErrStageFailed) {
				t.Fatalf("环自身出问题必须归口 ErrStageFailed，实得 %v", err)
			}
			if de.Stage != stageInternal {
				t.Fatalf("归口环节名应为 %q，实得 %q", stageInternal, de.Stage)
			}
			if de.Cause == nil {
				t.Fatal("环自身出问题的 Cause 不得为 nil：为空等于把它谎报成正常拒绝")
			}
			if tc.wantCause != nil && !errors.Is(err, tc.wantCause) {
				t.Fatalf("应能顺着 Cause 挖到根因 %v，实得 %v", tc.wantCause, err)
			}
			if !strings.Contains(de.Reason, tc.wantInText) {
				t.Fatalf("Reason 应带原文 %q（留痕要能定位），实得 %q", tc.wantInText, de.Reason)
			}
			if de.Retryable {
				t.Fatal("环自身出问题不可重试：重试只会再崩一次")
			}
		})
	}
}

// TestEvaluateStagesEmptyNameDeniedBeforeAnyRing 空名在**评估任何一环之前**就拒。
//
// 顺序也是契约：先跑环再查空名，等于让门禁为一个压根无法定位的调用白跑一遍。
func TestEvaluateStagesEmptyNameDeniedBeforeAnyRing(t *testing.T) {
	evaluated := 0
	ring := StageFunc{StageName: "gate", Fn: func(context.Context, Call) (Verdict, error) {
		evaluated++
		return Verdict{Allow: true}, nil
	}}

	err := EvaluateStages(context.Background(), []Stage{ring}, Call{})
	if err == nil {
		t.Fatal("空名应拒绝")
	}
	if evaluated != 0 {
		t.Fatalf("空名不该触达任何环，实得评估 %d 环", evaluated)
	}
	// 「压根没有可判定的对象」要能被认出来，而不是靠比对 Reason 文本。
	if !errors.Is(err, ErrEmptyName) {
		t.Fatalf("空名应归口 ErrEmptyName，实得 %v", err)
	}
	var de *DenyError
	if !errors.As(err, &de) || de.Stage != stagePrecondition {
		t.Fatalf("应指出是链前校验拒的，实得 %v", err)
	}
	if errors.Is(err, ErrStageFailed) {
		t.Fatal("空名不是「某一环坏了」，不该归口 ErrStageFailed")
	}
	if Retryable(err) {
		t.Fatal("空名不可重试：重试不会让空名变成合法名")
	}
}

// TestEvaluateStagesShortCircuitsAfterDeny 拒绝后不再评估后续环。
// 若仍评估，一环有副作用的门禁（计费、配额、留痕）会在已经拒绝的调用上白跑一遍。
func TestEvaluateStagesShortCircuitsAfterDeny(t *testing.T) {
	later := 0
	err := EvaluateStages(context.Background(), []Stage{
		deny("first", false),
		StageFunc{StageName: "later", Fn: func(context.Context, Call) (Verdict, error) {
			later++
			return Verdict{Allow: true}, nil
		}},
	}, Call{Name: "t"})
	if err == nil {
		t.Fatal("应被拒")
	}
	if later != 0 {
		t.Fatalf("拒绝后不得评估后续环，实得评估 %d 次", later)
	}
}

// TestEvaluateStagesPassesContextAndCallThrough 环拿到的就是调用方给的那份 ctx/Call。
// 求值入口把环排在了包里，但「一次调用是什么」的定义权仍在调用方手里。
func TestEvaluateStagesPassesContextAndCallThrough(t *testing.T) {
	type key struct{}
	want := Call{Name: "t", Server: "srv", Caller: "program", Args: `{"a":1}`}
	var gotKey any
	var gotCall Call
	ring := StageFunc{StageName: "gate", Fn: func(ctx context.Context, c Call) (Verdict, error) {
		gotKey, gotCall = ctx.Value(key{}), c
		return Verdict{Allow: true}, nil
	}}

	ctx := context.WithValue(context.Background(), key{}, "v")
	if err := EvaluateStages(ctx, []Stage{ring}, want); err != nil {
		t.Fatal(err)
	}
	if gotKey != "v" {
		t.Fatalf("ctx 应原样传到环上，实得 %v", gotKey)
	}
	if gotCall != want {
		t.Fatalf("Call 应原样传到环上，实得 %+v", gotCall)
	}
}

// TestEvaluateStagesNilRingFailsClosed 装配漏了一环（nil）必须关闸，且不得杀进程。
//
// 「不杀进程」不是修辞：这条用例跑得过，就说明它没把进程带走。取环名那一行
// 若直接调 nil 的 Name()，panic 会发生在 runStage 的 recover **之外**，
// 一次接线失误就升级成编排进程猝死——包文档承诺过这件事不会发生。
func TestEvaluateStagesNilRingFailsClosed(t *testing.T) {
	err := EvaluateStages(context.Background(), []Stage{nil}, Call{Name: "t"})
	if err == nil {
		t.Fatal("nil 环应拒绝")
	}
	if !errors.Is(err, ErrStageFailed) {
		t.Fatalf("nil 环属装配故障，应归口 ErrStageFailed，实得 %v", err)
	}
	var de *DenyError
	if !errors.As(err, &de) || de.Stage != stageInternal {
		t.Fatalf("应归口到 internal，实得 %v", err)
	}
}

// TestEvaluateStagesSignatureExposesNothing 钉住求值入口的完整签名：
// 入参只有 (ctx, 环表, 调用)，出参只有 error。
//
// 任何多出来的返回值都是给绕过留的门——回环节就能绕，回执行体更不必说。
// 反过来，入参里出现 Handler 也说明这条入口被设计成了「拿到执行体的路子」，
// 那与本包的不变量直接冲突。签名里两者都没有，这条不变量才成立
// （与 TestStagesDoesNotLeakHandler 同源）。
func TestEvaluateStagesSignatureExposesNothing(t *testing.T) {
	errIface := reflect.TypeOf((*error)(nil)).Elem()
	ctxIface := reflect.TypeOf((*context.Context)(nil)).Elem()
	got := reflect.TypeOf(EvaluateStages)

	if got.NumOut() != 1 || got.Out(0) != errIface {
		t.Fatalf("EvaluateStages 只能回 error，实得返回 %v", got)
	}
	wantIn := []reflect.Type{ctxIface, reflect.TypeOf([]Stage(nil)), reflect.TypeOf(Call{})}
	if got.NumIn() != len(wantIn) {
		t.Fatalf("入参应为 (ctx, 环表, 调用)，实得 %v", got)
	}
	for i, want := range wantIn {
		if got.In(i) != want {
			t.Fatalf("第 %d 个入参应为 %v，实得 %v", i, want, got.In(i))
		}
	}
}

// ── 漂移防护：链与求值入口必须给出同一个答案 ──

// TestChainDoAndEvaluateStagesAgree 防漂移：同一条环，走链和走求值入口必须同归口。
//
// 这是本文件存在的第二条理由。环一旦有两份排法，它们就会分叉，而且分叉是静默的：
// 下游那份把 panic 归口成守卫自己的名字、Cause 留空，于是
// 「这环自己崩了」与「这环正常拒绝了」在调用方眼里完全一样。
// 这里把「同一个 Call + 同一条环」在两条路径上的结局逐项比对，
// 任何一边改了归口口径而另一边没跟上，本用例立刻转红。
func TestChainDoAndEvaluateStagesAgree(t *testing.T) {
	cases := []struct {
		name   string
		stages []Stage
		call   Call
	}{
		{"全部放行", []Stage{allow("a"), allow("b")}, Call{Name: "t"}},
		{"中环拒绝", []Stage{allow("a"), deny("policy", true)}, Call{Name: "t"}},
		{"首环拒绝", []Stage{deny("policy", false), allow("a")}, Call{Name: "t"}},
		{"环报错", []Stage{allow("a"), errRing("flaky", errors.New("判定源不可用"))}, Call{Name: "t"}},
		{"环 panic", []Stage{allow("a"), panicRing("crasher", "环里炸了")}, Call{Name: "t"}},
		{"空名", []Stage{allow("a")}, Call{}},
		{"空名 + 空环表", nil, Call{}},
		{"nil 环", []Stage{nil}, Call{Name: "t"}},
		{"未装配环", nil, Call{Name: "t"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var rec Record
			hits := 0
			c, err := NewChain(okHandler(&hits), tc.stages, WithRecorder(func(r Record) { rec = r }))
			if err != nil {
				t.Fatal(err)
			}

			_, doErr := c.Do(context.Background(), tc.call)
			trace, evalErr := evaluateStages(context.Background(), tc.stages, tc.call)
			exposedErr := EvaluateStages(context.Background(), tc.stages, tc.call)

			if (doErr == nil) != (exposedErr == nil) {
				t.Fatalf("两条路径结局不一致：Do=%v 求值入口=%v", doErr, exposedErr)
			}
			if want, got := classify(doErr), classify(exposedErr); want != got {
				t.Fatalf("两条路径归口不一致：\n Do    = %+v\n 求值  = %+v", want, got)
			}
			if want, got := classify(evalErr), classify(exposedErr); want != got {
				t.Fatalf("导出的入口与本体不一致：%+v vs %+v", want, got)
			}

			// 分环留痕也必须一致：链留的痕不能比求值路径多/少一环。
			if len(rec.Stages) != len(trace) {
				t.Fatalf("留痕条数不一致：Do=%d 求值=%d", len(rec.Stages), len(trace))
			}
			for i := range trace {
				a, b := rec.Stages[i], trace[i]
				if a.Stage != b.Stage || a.Allow != b.Allow || a.Reason != b.Reason {
					t.Fatalf("第 %d 环留痕不一致：Do=%+v 求值=%+v", i, a, b)
				}
			}

			// 被拒/环故障时执行体一次都不该被触达。
			if doErr != nil && hits != 0 {
				t.Fatalf("未放行的调用不得触达执行体，实得 %d 次", hits)
			}
		})
	}
}

// classify 把一个结局压成调用方真正依赖的那几项，用于两条路径逐项比对。
type classification struct {
	allowed     bool
	stage       string
	reason      string
	retryable   bool
	causeNil    bool
	stageFailed bool
	emptyName   bool
}

func classify(err error) classification {
	if err == nil {
		return classification{allowed: true}
	}
	c := classification{
		stageFailed: errors.Is(err, ErrStageFailed),
		emptyName:   errors.Is(err, ErrEmptyName),
	}
	var de *DenyError
	if errors.As(err, &de) {
		c.stage = de.Stage
		c.reason = de.Reason
		c.retryable = de.Retryable
		c.causeNil = de.Cause == nil
	}
	return c
}
