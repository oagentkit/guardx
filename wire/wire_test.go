package wire

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oagentkit/guardx/toolfail"
)

// readWriter 把 Reader 与 Writer 拼成一个 ReadWriter（管道是单向的，协议要全双工）。
type readWriter struct {
	r io.Reader
	w io.Writer
}

func (rw *readWriter) Read(p []byte) (int, error)  { return rw.r.Read(p) }
func (rw *readWriter) Write(p []byte) (int, error) { return rw.w.Write(p) }

// channelPair 造一对全双工端：返回「子侧端」与「父侧端」。
//
// 两个 io.Pipe 组成全双工：p2c（父→子）与 c2p（子→父）。
func channelPair() (child, parent *readWriter, cleanup func()) {
	p2cR, p2cW := io.Pipe()
	c2pR, c2pW := io.Pipe()
	child = &readWriter{r: p2cR, w: c2pW}
	parent = &readWriter{r: c2pR, w: p2cW}
	cleanup = func() {
		_ = p2cR.Close()
		_ = p2cW.Close()
		_ = c2pR.Close()
		_ = c2pW.Close()
	}
	return child, parent, cleanup
}

// TestBidirectionalCall 子侧发请求 → 父侧处理 → 响应回子侧。
//
// 这是协议的基本闭环。**方向**：程序在子进程里（`host.<tool>()`），
// 所以子侧是发起方（Client），父侧是应答方（Server）。
func TestBidirectionalCall(t *testing.T) {
	child, parent, cleanup := channelPair()
	defer cleanup()

	server := NewServer(parent, func(ctx context.Context, req Request) (Response, error) {
		return Response{OK: true, Value: "OUT:" + req.Tool + ":" + req.Args}, nil
	})
	go func() { _ = server.Serve(context.Background()) }()

	client := NewClient(child)
	resp, err := client.Call(context.Background(), "get_logs", `{"host":"h1"}`)
	if err != nil {
		t.Fatalf("调用失败: %v", err)
	}
	if !resp.OK {
		t.Fatalf("应成功，实得 %+v", resp)
	}
	if resp.Value != "OUT:get_logs:{\"host\":\"h1\"}" {
		t.Errorf("值=%q，应为 OUT:get_logs:{\"host\":\"h1\"}", resp.Value)
	}
}

// TestBidirectionalCallFailure 失败分类跨进程同源（不变量 2）。
func TestBidirectionalCallFailure(t *testing.T) {
	child, parent, cleanup := channelPair()
	defer cleanup()

	server := NewServer(parent, func(ctx context.Context, req Request) (Response, error) {
		return Response{OK: false, Kind: string(toolfail.ClassPermissionDenied), Error: "没权限"}, nil
	})
	go func() { _ = server.Serve(context.Background()) }()

	client := NewClient(child)
	resp, err := client.Call(context.Background(), "danger", "")
	if err != nil {
		t.Fatalf("调用失败: %v", err)
	}
	if resp.OK {
		t.Fatal("应失败")
	}
	// 分类必须还是 toolfail 的分类（跨进程不失真）。
	if resp.Kind != string(toolfail.ClassPermissionDenied) {
		t.Errorf("分类=%q，应为 %s", resp.Kind, toolfail.ClassPermissionDenied)
	}
}

// TestConcurrentCallsRespondByID 响应按 id 关联（不变量 6）。
//
// 多个并发调用的返回顺序与请求顺序无关——本用例让父侧**逆序**回响应，
// 验证子侧仍能按 id 正确配对。
func TestConcurrentCallsRespondByID(t *testing.T) {
	child, parent, cleanup := channelPair()
	defer cleanup()

	const n = 5
	var got []Request
	go func() {
		for i := 0; i < n; i++ {
			var req Request
			if err := ReadFrame(parent.r, &req); err != nil {
				return
			}
			got = append(got, req)
		}
		// 逆序回响应。
		for i := len(got) - 1; i >= 0; i-- {
			_ = WriteFrame(parent.w, Response{V: Version, ID: got[i].ID, OK: true, Value: got[i].Tool})
		}
	}()

	client := NewClient(child)
	results := make([]string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tool := string(rune('a' + i))
			resp, err := client.Call(context.Background(), tool, "")
			if err != nil {
				t.Errorf("调用 %s 失败: %v", tool, err)
				return
			}
			results[i] = resp.Value
		}(i)
	}
	wg.Wait()
	for i := 0; i < n; i++ {
		want := string(rune('a' + i))
		if results[i] != want {
			t.Errorf("第 %d 个结果=%q，应为 %q（响应必须按 id 关联，不按到达顺序）", i, results[i], want)
		}
	}
}

// TestServerHandlesConcurrentCalls 并发处理：一次慢调用不阻塞其他调用。
//
// 这是「父侧在途上限」有意义的前提——若父侧串行处理，这个上限永远触发不了。
func TestServerHandlesConcurrentCalls(t *testing.T) {
	child, parent, cleanup := channelPair()
	defer cleanup()

	release := make(chan struct{})
	started := make(chan struct{}, 2)
	server := NewServer(parent, func(ctx context.Context, req Request) (Response, error) {
		started <- struct{}{}
		if req.Tool == "slow" {
			<-release
		}
		return Response{OK: true, Value: req.Tool}, nil
	})
	go func() { _ = server.Serve(context.Background()) }()

	client := NewClient(child)
	var wg sync.WaitGroup
	for _, tool := range []string{"slow", "fast"} {
		wg.Add(1)
		go func(tool string) {
			defer wg.Done()
			resp, err := client.Call(context.Background(), tool, "")
			if err != nil {
				t.Errorf("调用 %s 失败: %v", tool, err)
				return
			}
			if resp.Value != tool {
				t.Errorf("值=%q，应为 %q", resp.Value, tool)
			}
		}(tool)
	}
	// 两个 handler 都已进入 ⇒ 父侧是并发处理的。
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("父侧未并发处理（慢调用阻塞了其他调用）")
		}
	}
	close(release)
	wg.Wait()
}

// TestServerInflightLimit 在途调用有硬上限（不变量 4）。
//
// 超限时**回「超限」帧、不排队等**——排队等就等于没有上限（那十万个调用
// 仍然会把父侧堆满，只是慢一点）。
func TestServerInflightLimit(t *testing.T) {
	child, parent, cleanup := channelPair()
	defer cleanup()

	release := make(chan struct{})
	defer close(release)
	entered := make(chan struct{}, 4)
	server := NewServer(parent, func(ctx context.Context, req Request) (Response, error) {
		entered <- struct{}{}
		<-release
		return Response{OK: true}, nil
	}, WithMaxInflight(1))
	go func() { _ = server.Serve(context.Background()) }()

	client := NewClient(child)
	// 第一个调用占住唯一的在途名额。
	firstErr := make(chan error, 1)
	go func() {
		_, err := client.Call(context.Background(), "slow", "")
		firstErr <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("第一个调用未进入 handler")
	}
	// 第二个应被在途上限拒。
	resp, err := client.Call(context.Background(), "second", "")
	if err != nil {
		t.Fatalf("第二次调用应**回帧**（不是本地报错），实得 %v", err)
	}
	if resp.OK {
		t.Fatal("第二次调用应被在途上限拒")
	}
	if resp.Kind != string(toolfail.ClassRateLimited) {
		t.Errorf("分类=%q，应为 %s（容量类失败）", resp.Kind, toolfail.ClassRateLimited)
	}
	if !strings.Contains(resp.Error, "在途") {
		t.Errorf("错误信息应说明在途超限，实得 %q", resp.Error)
	}
}

// TestServerBudgetAuthority 预算的权威在父侧（不变量 3）。
func TestServerBudgetAuthority(t *testing.T) {
	child, parent, cleanup := channelPair()
	defer cleanup()

	server := NewServer(parent, func(ctx context.Context, req Request) (Response, error) {
		return Response{OK: true, Value: "x"}, nil
	}, WithBudget(Budget{MaxCalls: 1}))
	go func() { _ = server.Serve(context.Background()) }()

	client := NewClient(child)
	resp, err := client.Call(context.Background(), "first", "")
	if err != nil {
		t.Fatalf("第一次调用失败: %v", err)
	}
	if !resp.OK {
		t.Fatalf("第一次应成功，实得 %+v", resp)
	}
	// 第二次超配额：父侧记账拦下（不执行 handler）。
	resp, err = client.Call(context.Background(), "second", "")
	if err != nil {
		t.Fatalf("第二次调用应回帧，实得 %v", err)
	}
	if resp.OK {
		t.Fatal("第二次应被配额拒")
	}
	if resp.Kind != string(toolfail.ClassRateLimited) {
		t.Errorf("分类=%q，应为 %s", resp.Kind, toolfail.ClassRateLimited)
	}
	if !strings.Contains(resp.Error, "配额") {
		t.Errorf("错误信息应说明配额，实得 %q", resp.Error)
	}
	// 记账确实在父侧。
	calls, _ := server.budget.Used()
	if calls != 1 {
		t.Errorf("父侧记账=%d，应为 1（超限的那次不记账）", calls)
	}
}

// TestServerVersionMismatchRejected 版本不匹配即终止（不变量 1）。
func TestServerVersionMismatchRejected(t *testing.T) {
	child, parent, cleanup := channelPair()
	defer cleanup()
	server := NewServer(parent, func(ctx context.Context, req Request) (Response, error) {
		return Response{OK: true}, nil
	})
	// Serve 必须**先起**：io.Pipe 的 Write 同步等读端，没人读就永久阻塞。
	errCh := make(chan error, 1)
	go func() { errCh <- server.Serve(context.Background()) }()
	// 写一个错版本的请求帧（子侧 → 父侧）。
	if err := WriteFrame(child.w, Request{V: Version + 99, ID: "c-1", Tool: "t"}); err != nil {
		t.Fatalf("写帧失败: %v", err)
	}
	err := <-errCh
	if err == nil {
		t.Fatal("版本不匹配必须终止服务端循环")
	}
	if !strings.Contains(err.Error(), "版本不匹配") {
		t.Errorf("错误信息应说明版本不匹配，实得 %q", err.Error())
	}
}

// TestServerHandlerErrorBecomesUnknownClass Handler 报错 → 归 unknown（不可重试）。
func TestServerHandlerErrorBecomesUnknownClass(t *testing.T) {
	child, parent, cleanup := channelPair()
	defer cleanup()
	var got Response
	server := NewServer(parent, func(ctx context.Context, req Request) (Response, error) {
		return Response{}, errors.New("炸了")
	})
	go func() { _ = server.Serve(context.Background()) }()
	if err := WriteFrame(child.w, Request{V: Version, ID: "c-1", Tool: "t"}); err != nil {
		t.Fatalf("写帧失败: %v", err)
	}
	if err := ReadFrame(child.r, &got); err != nil {
		t.Fatalf("读帧失败: %v", err)
	}
	if got.OK {
		t.Fatal("应失败")
	}
	if got.Kind != string(toolfail.ClassUnknown) {
		t.Errorf("分类=%q，应为 %s（不可分类 = 不可重试）", got.Kind, toolfail.ClassUnknown)
	}
}

// TestServerEmptyKindBecomesUnknown Handler 说失败却没给分类 → 归 unknown。
func TestServerEmptyKindBecomesUnknown(t *testing.T) {
	child, parent, cleanup := channelPair()
	defer cleanup()
	var got Response
	server := NewServer(parent, func(ctx context.Context, req Request) (Response, error) {
		return Response{OK: false, Error: "没说类别"}, nil
	})
	go func() { _ = server.Serve(context.Background()) }()
	if err := WriteFrame(child.w, Request{V: Version, ID: "c-1", Tool: "t"}); err != nil {
		t.Fatalf("写帧失败: %v", err)
	}
	if err := ReadFrame(child.r, &got); err != nil {
		t.Fatalf("读帧失败: %v", err)
	}
	if got.Kind != string(toolfail.ClassUnknown) {
		t.Errorf("分类=%q，应为 %s（分类不得退化成自由字符串）", got.Kind, toolfail.ClassUnknown)
	}
}

// TestServerNoHandler 未装配处理器 → 明确失败，不静默放行。
func TestServerNoHandler(t *testing.T) {
	child, parent, cleanup := channelPair()
	defer cleanup()
	var got Response
	server := NewServer(parent, nil)
	go func() { _ = server.Serve(context.Background()) }()
	if err := WriteFrame(child.w, Request{V: Version, ID: "c-1", Tool: "t"}); err != nil {
		t.Fatalf("写帧失败: %v", err)
	}
	if err := ReadFrame(child.r, &got); err != nil {
		t.Fatalf("读帧失败: %v", err)
	}
	if got.OK {
		t.Fatal("应失败")
	}
	if got.Kind != string(toolfail.ClassPermanent) {
		t.Errorf("分类=%q，应为 %s", got.Kind, toolfail.ClassPermanent)
	}
}

// TestServerEOFEndsLoop 子进程正常退出：读到底即结束，不是错误。
func TestServerEOFEndsLoop(t *testing.T) {
	child, parent, cleanup := channelPair()
	// 关掉子侧的写端 → 父侧读到 EOF（子进程正常退出）。
	if c, ok := child.w.(*io.PipeWriter); ok {
		_ = c.Close()
	}
	defer cleanup()
	server := NewServer(parent, nil)
	if err := server.Serve(context.Background()); err != nil {
		t.Errorf("EOF 应是正常结束，实得 %v", err)
	}
}

// TestClientCancelPropagates 取消传播（不变量 5）。
func TestClientCancelPropagates(t *testing.T) {
	pr, pw := io.Pipe()
	defer func() { _ = pr.Close() }()
	defer func() { _ = pw.Close() }()
	client := NewClient(&readWriter{r: pr, w: io.Discard})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := client.Call(ctx, "t", "")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("应返回 ctx 取消，实得 %v", err)
	}
}

// TestClientEmptyIDAndTool 参数校验。
func TestClientEmptyIDAndTool(t *testing.T) {
	pr, pw := io.Pipe()
	defer func() { _ = pr.Close() }()
	defer func() { _ = pw.Close() }()
	client := NewClient(&readWriter{r: pr, w: io.Discard})
	if _, err := client.CallWithID(context.Background(), "", "t", ""); err == nil {
		t.Error("空 ID 必须被拒")
	}
	if _, err := client.CallWithID(context.Background(), "c-1", "", ""); err == nil {
		t.Error("空工具名必须被拒")
	}
}

// TestClientDisconnectedParent 父侧断了 → 子侧在途调用失败。
func TestClientDisconnectedParent(t *testing.T) {
	pr, pw := io.Pipe()
	// 写端用 Discard（写不失败），只有读端断——这样失败形态是「父侧连接已断」
	// 而不是「帧写出失败」（后者是写端也断时的形态）。
	client := NewClient(&readWriter{r: pr, w: io.Discard})
	_ = pw.Close()
	_ = pr.Close()
	_, err := client.Call(context.Background(), "t", "")
	if err == nil {
		t.Fatal("父侧断了应报错")
	}
	if !strings.Contains(err.Error(), "父侧连接已断") {
		t.Errorf("错误信息应说明父侧连接已断，实得 %q", err.Error())
	}
}

// TestClientVersionMismatchRejected 版本不匹配即终止（不变量 1）。
func TestClientVersionMismatchRejected(t *testing.T) {
	pr, pw := io.Pipe()
	defer func() { _ = pr.Close() }()
	defer func() { _ = pw.Close() }()
	client := NewClient(&readWriter{r: pr, w: io.Discard})
	// 父侧回一个错版本的响应帧。
	go func() {
		_ = WriteFrame(pw, Response{V: Version + 99, ID: "c-1", OK: true})
	}()
	_, err := client.Call(context.Background(), "t", "")
	if err == nil {
		t.Fatal("版本不匹配必须失败")
	}
}

// TestBudgetChargeNotCountedWhenExceeded 超限的那次不记账。
func TestBudgetChargeNotCountedWhenExceeded(t *testing.T) {
	b := Budget{MaxCalls: 1}
	if !b.charge(1, 0) {
		t.Fatal("第一次应记账成功")
	}
	if b.charge(1, 0) {
		t.Fatal("第二次应超限")
	}
	calls, _ := b.Used()
	if calls != 1 {
		t.Errorf("已用=%d，应为 1（超限的那次不记账）", calls)
	}
}

// TestBudgetBytesLimit 字节上限也生效。
func TestBudgetBytesLimit(t *testing.T) {
	b := Budget{MaxBytes: 10}
	if !b.charge(0, 10) {
		t.Fatal("刚好到上限应成功")
	}
	if b.charge(0, 1) {
		t.Fatal("超字节上限应被拒")
	}
	_, bytes := b.Used()
	if bytes != 10 {
		t.Errorf("已用字节=%d，应为 10", bytes)
	}
}

// TestServerClose 关闭是幂等的。
func TestServerClose(t *testing.T) {
	pr, pw := io.Pipe()
	defer func() { _ = pr.Close() }()
	defer func() { _ = pw.Close() }()
	server := NewServer(&readWriter{r: pr, w: pw}, nil)
	if err := server.Close(); err != nil {
		t.Errorf("首次关闭应无错: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Errorf("重复关闭应无错: %v", err)
	}
}

// TestClientClose 关闭是幂等的。
func TestClientClose(t *testing.T) {
	pr, pw := io.Pipe()
	defer func() { _ = pr.Close() }()
	defer func() { _ = pw.Close() }()
	client := NewClient(&readWriter{r: pr, w: io.Discard})
	if err := client.Close(); err != nil {
		t.Errorf("首次关闭应无错: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Errorf("重复关闭应无错: %v", err)
	}
}

// TestClientUniqueIDs 每次调用生成唯一 id。
func TestClientUniqueIDs(t *testing.T) {
	child, parent, cleanup := channelPair()
	defer cleanup()
	ids := make(chan string, 4)
	server := NewServer(parent, func(ctx context.Context, req Request) (Response, error) {
		ids <- req.ID
		return Response{OK: true}, nil
	})
	go func() { _ = server.Serve(context.Background()) }()
	client := NewClient(child)
	for i := 0; i < 3; i++ {
		if _, err := client.Call(context.Background(), "t", ""); err != nil {
			t.Fatalf("调用失败: %v", err)
		}
	}
	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		id := <-ids
		if seen[id] {
			t.Errorf("id 重复: %s", id)
		}
		seen[id] = true
		if !strings.HasPrefix(id, "c-") {
			t.Errorf("id=%q，应以 c- 开头", id)
		}
	}
	_ = fmt.Sprint()
}
