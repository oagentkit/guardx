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
type Starter struct {
	// w 写端（Start 帧从这里出去）。
	w io.Writer
	// r 读端（Result 帧从这里进来）。
	r io.Reader
	// writeMu 串行化写。
	writeMu sync.Mutex
}

// NewStarter 构造父侧启动器。
func NewStarter(rw io.ReadWriter) *Starter {
	return &Starter{w: rw, r: rw}
}

// Start 发送启动帧并等待子侧回报结果。
//
// 一次性语义：一次 Start 对应一次执行。子侧跑完（成功、失败、或被内核杀掉
// 都没回帧）时，父侧会在 ctx 超时或连接断开时拿到错误——**「子进程被 OOM 杀掉」
// 正是这条路径**：管道 EOF，不是「程序返回空」。
func (s *Starter) Start(ctx context.Context, start Start) (Result, error) {
	if err := checkStart(&start); err != nil {
		return Result{}, err
	}
	start.V = Version
	s.writeMu.Lock()
	err := WriteFrame(s.w, start)
	s.writeMu.Unlock()
	if err != nil {
		return Result{}, err
	}
	var res Result
	if err := ReadFrame(s.r, &res); err != nil {
		return Result{}, fmt.Errorf("wire: 执行域异常终止（未回报结果）: %w", err)
	}
	if err := checkVersion(res.V); err != nil {
		return Result{}, err
	}
	if err := checkResult(&res); err != nil {
		return Result{}, err
	}
	if res.ResultID != start.ResultID {
		return Result{}, fmt.Errorf("wire: 结果标识不匹配：期望 %s，收到 %s", start.ResultID, res.ResultID)
	}
	return res, nil
}
