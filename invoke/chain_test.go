package invoke

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/oekit/pkg/errors"
)

// allow 是一个恒放行的环节。
func allow(name string) Stage {
	return StageFunc{StageName: name, Fn: func(context.Context, Call) (Verdict, error) {
		return Verdict{Allow: true}, nil
	}}
}

// deny 是一个恒拒绝的环节。
func deny(name string, retryable bool) Stage {
	return StageFunc{StageName: name, Fn: func(context.Context, Call) (Verdict, error) {
		return Verdict{Allow: false, Reason: "策略不允许", Retryable: retryable}, nil
	}}
}

// okHandler 是一个成功返回的执行体，调用它会记一次。
func okHandler(calls *int) Handler {
	return func(_ context.Context, c Call) (Result, error) {
		*calls++
		return Result{Text: "结果:" + c.Name}, nil
	}
}

// ── 构造期 fail-closed ──

// TestNewChainRejectsNilHandler 钉住「空转的链」不成立。
//
// 为什么这条最要紧：一个不校验 handler 的 NewChain 会返回一条看起来能用的链，
// 而它对任何调用都不做审计——比构造失败危险得多，因为它不像是配置错误。
func TestNewChainRejectsNilHandler(t *testing.T) {
	c, err := NewChain(nil, []Stage{allow("x")})
	if c != nil || !errors.Is(err, ErrNoHandler) {
		t.Fatalf("nil handler 应构造失败，实得 chain=%v err=%v", c, err)
	}
}

// TestNewChainCopiesStageSlice 防调用方在构造后改自己的切片往链里塞环节。
// 链「构造后不可变」是并发安全的前提，共享底层数组会让这个前提失效。
func TestNewChainCopiesStageSlice(t *testing.T) {
	stages := []Stage{allow("a")}
	c, err := NewChain(okHandler(new(int)), stages)
	if err != nil {
		t.Fatal(err)
	}
	stages[0] = deny("b", false)
	if got := c.Stages(); len(got) != 1 || got[0] != "a" {
		t.Fatalf("链不应受构造后改切片影响，实得 %v", got)
	}
}

// ── 不可绕过：拒绝时执行体不得被触达 ──

// TestDeniedCallNeverReachesHandler 是本包存在理由的核心断言：
// 被拒的调用**不能**到达执行体。装饰器形态下这条靠自觉，链形态下它由构造保证。
func TestDeniedCallNeverReachesHandler(t *testing.T) {
	hits := 0
	c, err := NewChain(okHandler(&hits), []Stage{deny("gate", false)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(context.Background(), Call{Name: "t"}); err == nil {
		t.Fatal("被拒调用应返回错误")
	}
	if hits != 0 {
		t.Fatalf("被拒调用不得触达执行体，实得触达 %d 次", hits)
	}
}

// TestDenyShortCircuitsLaterStages 拒绝后不得再评估后续环节。
// 若仍评估，一环有副作用的门禁（计费、留痕、配额）会在已经拒绝的调用上白跑一遍。
func TestDenyShortCircuitsLaterStages(t *testing.T) {
	later := 0
	c, err := NewChain(okHandler(new(int)), []Stage{
		deny("first", false),
		StageFunc{StageName: "later", Fn: func(context.Context, Call) (Verdict, error) {
			later++
			return Verdict{Allow: true}, nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(context.Background(), Call{Name: "t"}); err == nil {
		t.Fatal("应被拒")
	}
	if later != 0 {
		t.Fatalf("拒绝后不得评估后续环节，实得评估 %d 次", later)
	}
}

// ── 阶段报错与 panic 都按拒绝处理 ──

// TestStageErrorDeniesInsteadOfPassing 钉住 fail-closed 的关键一条：
// 门禁环**自己报错**时按拒绝处理，不是「这环管不着、跳过」。
//
// 跳过等于把一次故障静默降级成不设防——正是本包要消灭的那类静默失效。
func TestStageErrorDeniesInsteadOfPassing(t *testing.T) {
	hits := 0
	boom := errors.New("判定源不可用")
	c, err := NewChain(okHandler(&hits), []Stage{
		StageFunc{StageName: "flaky", Fn: func(context.Context, Call) (Verdict, error) {
			return Verdict{Allow: true}, boom // 嘴上放行，实际报错——更该拒
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, got := c.Do(context.Background(), Call{Name: "t"})
	if got == nil {
		t.Fatal("阶段报错应返回错误")
	}
	if !errors.Is(got, ErrStageFailed) {
		t.Fatalf("应归口 ErrStageFailed，实得 %v", got)
	}
	if hits != 0 {
		t.Fatalf("阶段报错时不得触达执行体，实得 %d 次", hits)
	}
}

// TestStagePanicIsRecovered 门禁环 panic 必须被 recover 并转成拒绝。
//
// 这条对应真实故障：OpenCode 把工具执行搬进后台服务后，TUI 进程里的 recover
// 就够不着了，于是本该拦下 panic 的保护静默消失。链是唯一还在的进程内边界。
func TestStagePanicIsRecovered(t *testing.T) {
	hits := 0
	c, err := NewChain(okHandler(&hits), []Stage{
		StageFunc{StageName: "crasher", Fn: func(context.Context, Call) (Verdict, error) {
			panic("环里炸了")
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, got := c.Do(context.Background(), Call{Name: "t"})
	if got == nil {
		t.Fatal("环 panic 应转成错误而不是杀进程")
	}
	if !strings.Contains(got.Error(), "环里炸了") {
		t.Fatalf("错误应带 panic 原文（留痕要能定位），实得 %q", got)
	}
	if hits != 0 {
		t.Fatalf("环 panic 时不得触达执行体，实得 %d 次", hits)
	}
}

// TestHandlerPanicIsRecovered 执行体 panic 同样转成错误，不杀编排进程。
func TestHandlerPanicIsRecovered(t *testing.T) {
	c, err := NewChain(func(context.Context, Call) (Result, error) {
		panic("执行体炸了")
	}, []Stage{allow("gate")})
	if err != nil {
		t.Fatal(err)
	}
	_, got := c.Do(context.Background(), Call{Name: "t"})
	if got == nil || !errors.Is(got, ErrPanic) {
		t.Fatalf("执行体 panic 应转成 ErrPanic，实得 %v", got)
	}
	if !strings.Contains(got.Error(), "执行体炸了") {
		t.Fatalf("错误应带 panic 原文，实得 %q", got)
	}
}

// ── 空名不乐观放行 ──

// TestEmptyNameDenied 空工具名无法定位与审计，门禁不对它乐观放行。
// 这条与「目录内未加载 → 可重试」这类二分不同：空名不是「还没加载」，
// 它是压根没有可判定的对象。
func TestEmptyNameDenied(t *testing.T) {
	hits := 0
	c, err := NewChain(okHandler(&hits), []Stage{allow("gate")})
	if err != nil {
		t.Fatal(err)
	}
	_, got := c.Do(context.Background(), Call{})
	if got == nil {
		t.Fatal("空名应拒绝")
	}
	if Retryable(got) {
		t.Fatal("空名不可重试：重试不会让空名变成合法名")
	}
	if hits != 0 {
		t.Fatalf("空名不得触达执行体，实得 %d 次", hits)
	}
}

// ── 留痕：任何结局都恰好一条 ──

// TestExactlyOneRecordPerOutcome 是本包对「审计面不对称」的正面回答。
//
// 多一条会把一次调用算成两次，少一条等于这次调用没发生过——两个方向都要钉。
// 特别要覆盖 panic 路径：最需要留痕的时刻，恰恰最容易漏。
func TestExactlyOneRecordPerOutcome(t *testing.T) {
	ok := func(context.Context, Call) (Result, error) { return Result{Text: "x"}, nil }
	boom := func(context.Context, Call) (Result, error) { return Result{}, errors.New("执行失败") }
	stageErr := StageFunc{StageName: "e", Fn: func(context.Context, Call) (Verdict, error) {
		return Verdict{}, errors.New("判定失败")
	}}
	stagePanic := StageFunc{StageName: "p", Fn: func(context.Context, Call) (Verdict, error) {
		panic("环炸")
	}}
	handlerPanic := func(context.Context, Call) (Result, error) { panic("体炸") }

	cases := []struct {
		name    string
		stages  []Stage
		handler Handler
		call    Call
		allowed bool
	}{
		{"放行", []Stage{allow("g")}, ok, Call{Name: "t"}, true},
		{"拒绝", []Stage{deny("g", false)}, ok, Call{Name: "t"}, false},
		{"阶段报错", []Stage{stageErr}, ok, Call{Name: "t"}, false},
		{"阶段 panic", []Stage{stagePanic}, ok, Call{Name: "t"}, false},
		{"执行体报错", []Stage{allow("g")}, boom, Call{Name: "t"}, false},
		{"执行体 panic", []Stage{allow("g")}, handlerPanic, Call{Name: "t"}, false},
		{"空名", []Stage{allow("g")}, ok, Call{}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var recs []Record
			c, err := NewChain(tc.handler, tc.stages, WithRecorder(func(r Record) {
				mu.Lock()
				recs = append(recs, r)
				mu.Unlock()
			}))
			if err != nil {
				t.Fatal(err)
			}
			_, _ = c.Do(context.Background(), tc.call)

			if len(recs) != 1 {
				t.Fatalf("每次调用应恰好一条留痕，实得 %d 条", len(recs))
			}
			r := recs[0]
			if r.Allowed != tc.allowed {
				t.Fatalf("Allowed 应为 %v，实得 %v", tc.allowed, r.Allowed)
			}
			// 失败结局必须带 Err：一条没有 Err 的失败记录读起来和成功记录没区别。
			if !tc.allowed && r.Err == nil {
				t.Fatal("失败留痕必须带 Err")
			}
			if tc.allowed && r.Err != nil {
				t.Fatalf("放行留痕不该带 Err，实得 %v", r.Err)
			}
		})
	}
}

// TestRecordCarriesDenyReason 留痕必须回答「哪一环拒的、为什么」。
// 只记「调用失败」的话，审计无法定位到具体策略，等于没有审计。
func TestRecordCarriesDenyReason(t *testing.T) {
	var got Record
	c, err := NewChain(okHandler(new(int)), []Stage{
		allow("first"), deny("policy", true),
	}, WithRecorder(func(r Record) { got = r }))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Do(context.Background(), Call{Name: "t", Server: "srv", Caller: "agent"})

	if got.Call.Name != "t" || got.Call.Server != "srv" || got.Call.Caller != "agent" {
		t.Fatalf("留痕应带回调用上下文，实得 %+v", got.Call)
	}
	if len(got.Stages) != 2 {
		t.Fatalf("两环应各留一条，实得 %d 条", len(got.Stages))
	}
	if got.Stages[0].Stage != "first" || !got.Stages[0].Allow {
		t.Fatalf("首环应放行且被记录，实得 %+v", got.Stages[0])
	}
	if got.Stages[1].Stage != "policy" || got.Stages[1].Allow {
		t.Fatalf("次环应拒绝且被记录，实得 %+v", got.Stages[1])
	}
}

// ── 重试判定 ──

// TestRetryableOnlyWhenStageSays 认不出的错误一律不可重试（fail-closed）。
// 门禁两类结局的差别只在「是否可恢复」上，猜错的代价不是少重试一次，
// 而是不停重复一个永远不会成功的调用。
func TestRetryableOnlyWhenStageSays(t *testing.T) {
	for _, tc := range []struct {
		name     string
		retry    bool
		wantErr  error
		wantWant bool
	}{
		{"声明可重试", true, nil, true},
		{"声明不可重试", false, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := NewChain(okHandler(new(int)), []Stage{deny("g", tc.retry)})
			_, err := c.Do(context.Background(), Call{Name: "t"})
			if got := Retryable(err); got != tc.wantWant {
				t.Fatalf("Retryable 应为 %v，实得 %v", tc.wantWant, got)
			}
		})
	}

	// 非门禁错误一律不可重试。
	if Retryable(errors.New("随手一个错误")) {
		t.Fatal("认不出的错误不应判为可重试")
	}
	if Retryable(nil) {
		t.Fatal("nil 不该判为可重试")
	}
}

// TestNilStageFnDenies 配漏一环（Fn 为 nil）应拒绝而不是放行。
// 漏配是装配期最常见的错，而漏配的后果必须是关闸而不是开门。
func TestNilStageFnDenies(t *testing.T) {
	hits := 0
	c, err := NewChain(okHandler(&hits), []Stage{StageFunc{StageName: "forgot"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(context.Background(), Call{Name: "t"}); err == nil {
		t.Fatal("漏配判定函数应拒绝")
	}
	if hits != 0 {
		t.Fatalf("漏配时不得触达执行体，实得 %d 次", hits)
	}
}

// TestStagesDoesNotLeakHandler Stages 只回环节名，不回环节本体。
//
// 任何能把执行体或判定函数交出去的出口，都是给绕过留的门——这条断言
// 钉的是「返回类型里没有它们」，将来若有人加一个回传 Stage 的方法，
// 编译期不会响，但这里的语义会破。
func TestStagesDoesNotLeakHandler(t *testing.T) {
	c, err := NewChain(okHandler(new(int)), []Stage{allow("a"), allow("b")})
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Stages(); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("应只回环节名，实得 %v", got)
	}
}

// TestConcurrentDoSharesOneChain 链构造后不可变，并发调用不得竞态。
// 用例在 -race 下才有意义（仓库的 make test 带 -race）。
func TestConcurrentDoSharesOneChain(t *testing.T) {
	var mu sync.Mutex
	total := 0
	// 执行体刻意用无状态实现：并发用例要验的是**链**在并发下安全，
	// 拿一个自己都不安全的计数器当执行体，验出来的是测试自己的竞态，不是链的。
	c, err := NewChain(func(context.Context, Call) (Result, error) {
		return Result{Text: "ok"}, nil
	}, []Stage{allow("g")},
		WithRecorder(func(Record) {
			mu.Lock()
			total++
			mu.Unlock()
		}))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Do(context.Background(), Call{Name: "t"}); err != nil {
				t.Errorf("并发调用不应失败: %v", err)
			}
		}()
	}
	wg.Wait()
	if total != 32 {
		t.Fatalf("32 次调用应留 32 条痕，实得 %d", total)
	}
}

// TestResultPassthrough 放行时出参原样透传（含结构化出参），不被链改写。
func TestResultPassthrough(t *testing.T) {
	want := Result{Text: "文本", Structured: []byte(`{"k":1}`)}
	c, err := NewChain(func(context.Context, Call) (Result, error) { return want, nil },
		[]Stage{allow("g")})
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Do(context.Background(), Call{Name: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Text != want.Text || string(got.Structured) != string(want.Structured) {
		t.Fatalf("出参应原样透传，实得 %+v", got)
	}
}
