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
	// writeMu 串行化写。
	writeMu sync.Mutex
}

// NewRunner 构造子侧启动通道对端。
func NewRunner(rw io.ReadWriter) *Runner {
	return &Runner{r: rw, w: rw}
}

// AwaitStart 等父侧下发一次执行的启动帧。
//
// 子侧的典型流程：连上启动通道 → AwaitStart（父侧告诉它跑什么）→ 跑程序
// （期间用**另一条**调用通道的 Client 请求工具）→ SendResult 回报结果。
//
// **只等一帧**——一次执行一个 Start。
func (r *Runner) AwaitStart(ctx context.Context) (*Start, error) {
	var start Start
	if err := ReadFrame(r.r, &start); err != nil {
		return nil, fmt.Errorf("wire: 读启动帧失败: %w", err)
	}
	if err := checkVersion(start.V); err != nil {
		return nil, err
	}
	if err := checkStart(&start); err != nil {
		return nil, err
	}
	return &start, nil
}

// SendResult 回报一次执行的结果。
func (r *Runner) SendResult(res Result) error {
	res.V = Version
	if err := checkResult(&res); err != nil {
		return err
	}
	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	return WriteFrame(r.w, res)
}
