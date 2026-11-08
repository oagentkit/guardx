package wire

import (
	"context"
	"fmt"
	"io"
	"sync"
)

// Runner 子侧启动通道的对端：收父侧下发的 Start、回报执行结果。
//
// # 与 Client 的分工（两条通道，两个方向）
//
//	启动通道：父侧 Starter  ←→  子侧 Runner   （一次执行：1 个 Start + 1 个 Result）
//	调用通道：父侧 Server  ←→  子侧 Client   （N 次工具调用）
//
// **两条通道必须是两条连接**。若共用一条，「读到的这帧是 Start 还是 Response」
// 就得靠猜——而两者的 JSON 形状不同（Request/Response 有 tool/id，Start 有
// program/bindings），猜错的后果是「字段读成了另一个意思」，那是最难查的一类
// 协议 bug。故本包把两个方向的四种角色各给一个类型。
type Runner struct {
	// r 读端（Start 帧从这里进来）。
	r io.Reader
	// w 写端（Result 帧从这里出去）。
	w io.Writer
	// closer 底层连接（实现 io.Closer 时）。ctx 兜底路径用它解除阻塞读（#79）。
	closer io.Closer
	// closeOnce 连接只关一次。
	closeOnce sync.Once
	// writeMu 串行化写。
	writeMu sync.Mutex
}

// NewRunner 构造子侧启动通道对端。
func NewRunner(rw io.ReadWriter) *Runner {
	rn := &Runner{r: rw, w: rw}
	if c, ok := rw.(io.Closer); ok {
		rn.closer = c
	}
	return rn
}

// closeConn 关底层连接（幂等；无可关连接时为空操作）。
//
// ctx 兜底路径专用：父侧迟迟不下发（或已死掉但连接未断）时，子侧靠它
// 自我了断——连接断开是协议里最强的取消信号（不变量 5）。
func (rn *Runner) closeConn() {
	if rn.closer == nil {
		return
	}
	rn.closeOnce.Do(func() {
		// 关连接产生的错误没有可采取的动作（连接本来就在被丢弃），
		// 记入忽略——这不是吞判定错误，是停机路径。
		_ = rn.closer.Close()
	})
}

// AwaitStart 等父侧下发一次执行的启动帧。
//
// 子侧的典型流程：连上启动通道 → AwaitStart（父侧告诉它跑什么）→ 跑程序
// （期间用**另一条**调用通道的 Client 请求工具）→ SendResult 回报结果。
//
// **只等一帧**——一次执行一个 Start。
//
// ctx 到期或取消时**必然返回**（#79）：主动关底层连接（可关时）解除阻塞读，
// 返回包装了 ctx.Err() 的错误，不再无期等父侧。底层不实现 io.Closer 时
// ctx 路径仍会返回（#102：此刻不等读 goroutine 退出——等不到，goroutine
// 要等连接自然断开才退出），但阻塞中的读 goroutine 要等连接自然断开才退出。
func (rn *Runner) AwaitStart(ctx context.Context) (*Start, error) {
	type outcome struct {
		start *Start
		err   error
	}
	done := make(chan outcome, 1)
	goSafe(func() {
		var start Start
		if err := ReadFrame(rn.r, &start); err != nil {
			done <- outcome{err: fmt.Errorf("wire: 读启动帧失败: %w", err)}
			return
		}
		if err := checkVersion(start.V); err != nil {
			done <- outcome{err: err}
			return
		}
		if err := checkStart(&start); err != nil {
			done <- outcome{err: err}
			return
		}
		done <- outcome{start: &start}
	})
	select {
	case o := <-done:
		return o.start, o.err
	case <-ctx.Done():
		// 父侧不下发：关连接解除阻塞读，本侧自我了断（#79）。
		rn.closeConn()
		if rn.closer != nil {
			<-done // 可关连接：close 已解除阻塞中的读，等 goroutine 退出，不泄漏。
		}
		// #102：closer == nil 时阻塞中的读解除不了——等读 goroutine 退出
		// 等于等连接自然断开，会把 godoc 承诺「必然返回」的 ctx 路径重新
		// 挂死。直接返回，goroutine 留守至连接自然断开（类型 godoc 已写明
		// 的既有限制）。done 有缓冲，goroutine 最终退出时不会阻塞在发送上。
		return nil, fmt.Errorf("wire: 等待启动帧时 ctx 到期（父侧未下发）: %w", ctx.Err())
	}
}

// SendResult 回报一次执行的结果。
func (rn *Runner) SendResult(res Result) error {
	res.V = Version
	if err := checkResult(&res); err != nil {
		return err
	}
	rn.writeMu.Lock()
	defer rn.writeMu.Unlock()
	return WriteFrame(rn.w, res)
}
