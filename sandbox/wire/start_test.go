package wire

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

// TestStartResultRoundTrip 父侧发 Start → 子侧收 → 子侧回 Result → 父侧拿到。
//
// 这是「一次执行」的完整闭环，与工具调用闭环（Client↔Server）是**两条独立通道**。
func TestStartResultRoundTrip(t *testing.T) {
	child, parent, cleanup := channelPair()
	defer cleanup()

	// 子侧：等 Start → 回 Result。
	go func() {
		rn := NewRunner(child)
		start, err := rn.AwaitStart(context.Background())
		if err != nil {
			return
		}
		_ = rn.SendResult(Result{
			ResultID: start.ResultID,
			OK:       true,
			Value:    "done:" + start.Program,
			Calls:    3,
			Bytes:    42,
		})
	}()

	// 父侧：发 Start → 等 Result。
	st := NewStarter(parent)
	res, err := st.Start(context.Background(), Start{
		Program:  "return 1",
		Bindings: []StartBinding{{Name: "get_logs", Signature: "get_logs(host, count)"}},
		Budget:   StartBudget{MaxCalls: 10, MaxMemory: 1 << 20},
		ResultID: "r-1",
	})
	if err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	if !res.OK {
		t.Fatalf("应成功，实得 %+v", res)
	}
	if res.Value != "done:return 1" {
		t.Errorf("值=%q，应为 done:return 1", res.Value)
	}
	if res.Calls != 3 || res.Bytes != 42 {
		t.Errorf("对账字段不对: calls=%d bytes=%d，应为 3 / 42", res.Calls, res.Bytes)
	}
}

// TestStarterReportsDomainTermination 子进程被内核杀掉 ⇒ 管道 EOF ⇒ 「执行域异常终止」。
//
// 这条路径是「真兜底」的判据：内存超限被内核杀掉的子进程**不会回 Result 帧**，
// 父侧必须把它识别成「执行域异常终止」，而不是「程序返回空」。
func TestStarterReportsDomainTermination(t *testing.T) {
	pr, pw := io.Pipe()
	defer func() { _ = pr.Close() }()
	defer func() { _ = pw.Close() }()

	st := NewStarter(&readWriter{r: pr, w: io.Discard})
	// 模拟子进程被 SIGKILL：写端直接关闭（无任何回帧）。
	_ = pw.Close()
	_, err := st.Start(context.Background(), Start{Program: "x", ResultID: "r-1"})
	if err == nil {
		t.Fatal("子进程异常终止必须报错")
	}
	if !strings.Contains(err.Error(), "执行域异常终止") {
		t.Errorf("错误信息应说明执行域异常终止，实得 %q", err.Error())
	}
}

// TestStarterRejectsMissingResultID 缺 result_id 即拒。
func TestStarterRejectsMissingResultID(t *testing.T) {
	pr, pw := io.Pipe()
	defer func() { _ = pr.Close() }()
	defer func() { _ = pw.Close() }()
	st := NewStarter(&readWriter{r: pr, w: io.Discard})
	if _, err := st.Start(context.Background(), Start{Program: "x"}); err == nil {
		t.Error("缺 result_id 必须被拒")
	}
}

// TestStarterRejectsMismatchedResultID 结果标识不匹配即拒。
//
// 标识对不上意味着「拿到的不是这次执行的结果」——那比没有结果更危险。
func TestStarterRejectsMismatchedResultID(t *testing.T) {
	child, parent, cleanup := channelPair()
	defer cleanup()
	go func() {
		rn := NewRunner(child)
		if _, err := rn.AwaitStart(context.Background()); err != nil {
			return
		}
		_ = rn.SendResult(Result{ResultID: "别人的", OK: true})
	}()
	st := NewStarter(parent)
	_, err := st.Start(context.Background(), Start{Program: "x", ResultID: "r-1"})
	if err == nil {
		t.Fatal("标识不匹配必须被拒")
	}
	if !strings.Contains(err.Error(), "标识不匹配") {
		t.Errorf("错误信息应说明标识不匹配，实得 %q", err.Error())
	}
}

// TestClientAwaitStartVersionMismatch Start 帧版本不匹配即拒（不变量 1）。
func TestClientAwaitStartVersionMismatch(t *testing.T) {
	pr, pw := io.Pipe()
	defer func() { _ = pr.Close() }()
	defer func() { _ = pw.Close() }()
	go func() {
		_ = WriteFrame(pw, Start{V: Version + 99, ResultID: "r-1"})
	}()
	rn := NewRunner(&readWriter{r: pr, w: io.Discard})
	_, err := rn.AwaitStart(context.Background())
	if err == nil {
		t.Fatal("版本不匹配必须被拒")
	}
	if !strings.Contains(err.Error(), "版本不匹配") {
		t.Errorf("错误信息应说明版本不匹配，实得 %q", err.Error())
	}
}

// TestClientAwaitStartMissingResultID 缺 result_id 即拒。
func TestClientAwaitStartMissingResultID(t *testing.T) {
	pr, pw := io.Pipe()
	defer func() { _ = pr.Close() }()
	defer func() { _ = pw.Close() }()
	go func() {
		_ = WriteFrame(pw, Start{V: Version})
	}()
	rn := NewRunner(&readWriter{r: pr, w: io.Discard})
	_, err := rn.AwaitStart(context.Background())
	if err == nil {
		t.Fatal("缺 result_id 必须被拒")
	}
}

// TestStartCarriesBindingsAndBudget Start 帧带着绑定清单与预算要求。
//
// 父侧交的是**清单**（名字 + 调用形态）不是**实现**——实现留在父侧，
// 子侧通过工具调用帧请求执行。这正是跨进程的意义。
func TestStartCarriesBindingsAndBudget(t *testing.T) {
	child, parent, cleanup := channelPair()
	defer cleanup()
	got := make(chan Start, 1)
	go func() {
		rn := NewRunner(child)
		s, err := rn.AwaitStart(context.Background())
		if err == nil {
			got <- *s
		}
	}()
	st := NewStarter(parent)
	go func() {
		_, _ = st.Start(context.Background(), Start{
			Program:  "p",
			Bindings: []StartBinding{{Name: "a"}, {Name: "b", Signature: "b(x)"}},
			Budget:   StartBudget{WallClock: time.Second, MaxCalls: 5, MaxMemory: 1 << 20},
			ResultID: "r-1",
		})
	}()
	select {
	case s := <-got:
		if len(s.Bindings) != 2 {
			t.Errorf("绑定清单=%d 条，应为 2", len(s.Bindings))
		}
		if s.Bindings[1].Signature != "b(x)" {
			t.Errorf("调用形态=%q，应为 b(x)", s.Bindings[1].Signature)
		}
		if s.Budget.MaxMemory != 1<<20 {
			t.Errorf("内存要求=%d，应为 %d", s.Budget.MaxMemory, 1<<20)
		}
		if s.Budget.WallClock != time.Second {
			t.Errorf("墙钟=%v，应为 1s", s.Budget.WallClock)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("子侧未收到 Start")
	}
}
