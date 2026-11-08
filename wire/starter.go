package wire

import (
	"context"
	"fmt"
	"io"
	"sync"
)

// Starter 父侧启动器：把一次执行的启动信息发给子侧，并收回结果。
//
// # 为什么单独一个类型（不塞进 Server）
//
// Server 是**应答方**（子侧发起工具调用，父侧应答）；Starter 是**发起方**
// （父侧告诉子侧跑什么，子在回报结果）。两者方向相反、职责不同，
// 塞进一个类型会让「谁在等谁」变得要看实现才知道。
//
// # 启动通道与调用通道是**两条**
//
// 启动是一次性的（发一帧 Start、收一帧 Result），工具调用是多次的
// （N 次 Request/Response）。混在一条连接上则「读到的那帧是哪种」要靠猜。
// 故 Starter 用自己的连接；后端起子进程时开两条管道（启动 + 调用）。
//
// # ctx 兜底（#79）
//
// 子程序**活着但不回帧**（死循环、被注入的劣化代码——正是 wire 隔离的威胁面）
// 时管道不会自己断，阻塞读永远不会醒：ctx 到期/取消时本类型会**主动关掉底层
// 连接**（实现 io.Closer 时）——一来解除阻塞中的读写，二来让子侧读到 EOF 自行
// 终止（不变量 5：管道关闭本身就是最强的取消信号）。故 Start 在「ctx 超时」
// 与「连接断开」两种情形下都**必然返回错误**，不会挂死。
//
// 底层连接不实现 io.Closer 时 ctx 路径仍会返回，但阻塞中的读 goroutine 要等
// 连接自然断开才退出（#102：此刻**不等** goroutine 退出——同步管道的读写
// 只有对端或 Close 能解除，等不到就得直接返回）；后端装配时请给启动通道
// 一条可关的连接。
type Starter struct {
	// w 写端（Start 帧从这里出去）。
	w io.Writer
	// r 读端（Result 帧从这里进来）。
	r io.Reader
	// closer 底层连接（实现 io.Closer 时）。ctx 兜底与重复关闭都用它。
	closer io.Closer
	// closeOnce 连接只关一次。
	closeOnce sync.Once
	// writeMu 串行化写。
	writeMu sync.Mutex
}

// NewStarter 构造父侧启动器。
func NewStarter(rw io.ReadWriter) *Starter {
	s := &Starter{w: rw, r: rw}
	if c, ok := rw.(io.Closer); ok {
		s.closer = c
	}
	return s
}

// closeConn 关底层连接（幂等；无可关连接时为空操作）。
//
// ctx 兜底路径专用：连接断开既是给子侧的取消信号（不变量 5），
// 也是解除本侧阻塞读写的唯一手段（同步管道没有别的打断办法）。
func (s *Starter) closeConn() {
	if s.closer == nil {
		return
	}
	s.closeOnce.Do(func() {
		// 关连接产生的错误没有可采取的动作（连接本来就在被丢弃），
		// 记入忽略——这不是吞判定错误，是停机路径。
		_ = s.closer.Close()
	})
}

// Start 发送启动帧并等待子侧回报结果。
//
// 一次性语义：一次 Start 对应一次执行。子侧跑完（成功、失败、或被内核杀掉
// 都没回帧）时，父侧会在 ctx 超时或连接断开时拿到错误——**「子进程被 OOM
// 杀掉」正是这条路径**：管道 EOF，不是「程序返回空」。
//
// ctx 到期或取消时**必然返回**（#79）：先关底层连接（可关时）解除阻塞、
// 通知子侧终止，再返回包装了 ctx.Err() 的错误。写帧阶段（子侧连 Start
// 都不读）同样被 ctx 兜住。
func (s *Starter) Start(ctx context.Context, start Start) (Result, error) {
	if err := checkStart(&start); err != nil {
		return Result{}, err
	}
	start.V = Version
	// 写阶段也要可中断：同步管道（io.Pipe / net.Pipe / OS 管道）的写
	// 与读一样会因对端装死而永久阻塞。
	if err := s.writeStart(ctx, start); err != nil {
		return Result{}, err
	}
	return s.awaitResult(ctx, start.ResultID)
}

// writeStart 在 ctx 约束下写出 Start 帧。
func (s *Starter) writeStart(ctx context.Context, start Start) error {
	type outcome struct{ err error }
	done := make(chan outcome, 1)
	goSafe(func() {
		s.writeMu.Lock()
		defer s.writeMu.Unlock()
		done <- outcome{err: WriteFrame(s.w, start)}
	})
	select {
	case o := <-done:
		return o.err
	case <-ctx.Done():
		// 关连接解除阻塞中的写（对端装死、永远不读 Start 时）。
		s.closeConn()
		if s.closer != nil {
			<-done // 可关连接：close 已解除阻塞中的写，等 goroutine 退出，不泄漏。
		}
		// #102：closer == nil 时没有任何手段解除阻塞中的写（同步管道的
		// 读写只能靠对端或 Close 解除）——等写 goroutine 退出等于等连接
		// 自然断开，会把 godoc 承诺「必然返回」的 ctx 路径重新挂死（#79
		// 修回的残留）。直接返回；goroutine 留守至连接自然断开（类型
		// godoc 已写明的既有限制）。done 有缓冲，goroutine 最终退出时
		// 不会阻塞在发送上。
		return fmt.Errorf("wire: 发送启动帧时 ctx 到期（子侧未接收）: %w", ctx.Err())
	}
}

// awaitResult 在 ctx 约束下等待子侧的 Result 帧。
func (s *Starter) awaitResult(ctx context.Context, resultID string) (Result, error) {
	type outcome struct {
		res Result
		err error
	}
	done := make(chan outcome, 1)
	goSafe(func() {
		var res Result
		err := ReadFrame(s.r, &res)
		done <- outcome{res: res, err: err}
	})
	select {
	case o := <-done:
		if o.err != nil {
			return Result{}, fmt.Errorf("wire: 执行域异常终止（未回报结果）: %w", o.err)
		}
		if err := checkVersion(o.res.V); err != nil {
			return Result{}, err
		}
		if err := checkResult(&o.res); err != nil {
			return Result{}, err
		}
		if o.res.ResultID != resultID {
			return Result{}, fmt.Errorf("wire: 结果标识不匹配：期望 %s，收到 %s", resultID, o.res.ResultID)
		}
		return o.res, nil
	case <-ctx.Done():
		// 子程序活着但不回帧：管道不会自己断，必须父侧主动断。
		// 关连接同时解除阻塞中的读，之后子侧读到 EOF 自行终止（不变量 5）。
		s.closeConn()
		if s.closer != nil {
			<-done // 可关连接：close 已解除阻塞中的读，等 goroutine 退出，不泄漏。
		}
		// #102：closer == nil 时阻塞中的读解除不了——等读 goroutine 退出
		// 等于等连接自然断开，会把 ctx 路径重新挂死。直接返回，goroutine
		// 留守至连接自然断开（类型 godoc 已写明的既有限制）。
		return Result{}, fmt.Errorf("wire: 等待执行结果时 ctx 到期（子程序未回报）: %w", ctx.Err())
	}
}
