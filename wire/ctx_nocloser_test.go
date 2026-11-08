package wire

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// 本文件钉 guardx#102 的回归：底层管道不实现 io.Closer 时，ctx 兜底路径必须
// 仍然返回——这是类型 godoc 明文承诺的形态（goroutine 留守到连接自然断开是
// 文档化的既有限制，但 Start / AwaitStart 本身不得挂死）。
// #79 修回的残留是：ctx 到期分支在 closeConn() 之后无条件等读/写 goroutine
// 退出，而无可关连接时那个 goroutine 要等到连接自然断开才会退出——等待本身
// 把 godoc 承诺「必然返回」的路径重新挂死了。

// noCloserRW 把 net.Conn 的 Close 藏掉：只剩 io.Reader + io.Writer，
// NewStarter / NewRunner 的 io.Closer 断言落空——正是 #102 的复现前提。
type noCloserRW struct {
	io.Reader
	io.Writer
}

func newNoCloserConn() (rw *noCloserRW, c1, c2 net.Conn) {
	c1, c2 = net.Pipe()
	return &noCloserRW{Reader: c1, Writer: c1}, c1, c2
}

// TestStarterCtxReturnsWithoutCloserWritePhase 子侧完全不读：写阶段挂死，
// ctx 到期必须返回——即便底层管道不可关。
func TestStarterCtxReturnsWithoutCloserWritePhase(t *testing.T) {
	rw, c1, _ := newNoCloserConn()
	defer func() { _ = c1.Close() }() // 收尾：解除留守 goroutine 的阻塞

	st := NewStarter(rw)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := st.Start(ctx, Start{Program: "x", ResultID: "r-1"})
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("错误应可按 ctx 期限判定，实得 %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("不可关管道上 ctx 到期后 Start 仍未返回（#102 挂死回归）")
	}
}

// TestStarterCtxReturnsWithoutCloserAwaitPhase 子侧读走 Start 帧但永不回帧：
// 等结果阶段挂死，ctx 到期必须返回——即便底层管道不可关。
func TestStarterCtxReturnsWithoutCloserAwaitPhase(t *testing.T) {
	rw, c1, c2 := newNoCloserConn()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()

	// 子侧读走 Start（让父侧写阶段完成）之后装死。
	go func() {
		var extra Start
		_ = ReadFrame(c2, &extra)
	}()

	st := NewStarter(rw)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := st.Start(ctx, Start{Program: "x", ResultID: "r-2"})
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("错误应可按 ctx 期限判定，实得 %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("不可关管道上 ctx 到期后 Start 卡在等结果阶段仍未返回（#102 挂死回归）")
	}
}

// TestRunnerAwaitStartReturnsWithoutCloser 父侧永不下发：子侧 AwaitStart 在
// ctx 到期时必须返回——即便底层管道不可关。
func TestRunnerAwaitStartReturnsWithoutCloser(t *testing.T) {
	rw, c1, _ := newNoCloserConn()
	defer func() { _ = c1.Close() }()

	rn := NewRunner(rw)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := rn.AwaitStart(ctx)
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("错误应可按 ctx 期限判定，实得 %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("不可关管道上 ctx 到期后 AwaitStart 仍未返回（#102 挂死回归）")
	}
}
