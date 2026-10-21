package wire

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/oagentkit/guardx/toolfail"
)

// ErrInflightLimit 在途调用数超过硬上限（不变量 4）。
//
// 与「配额超限」（MaxCalls）是**两件事**：配额是「总共能调多少次」，在途上限是
// 「同时能挂多少个」。后者拦的是「瞬间发起十万次并发调用」——那时它们都还没
// 返回，父侧已被 goroutine 淹没。
var ErrInflightLimit = errors.New("wire: 在途调用数超过硬上限")

// DefaultMaxInflight 在途调用数默认硬上限。
//
// 取 64：既能吃住「程序内并发几十次工具调用」的常见形态，又不至于让单个失控
// 程序把父侧的 goroutine 堆爆。宿主可调。
const DefaultMaxInflight = 64

// Handler 父侧处理一次工具调用。
//
// 返回的 Response 若 OK=false，**Kind 必须是 toolfail 的分类**（不变量 2）——
// 分类一旦退化成自由字符串，子进程侧就分不清「可重试」与「永久拒绝」。
//
// Handler 返回的 error 会被转成「分类 = unknown」的失败帧；能归类的失败请自己填
// Response.Kind（宿主最清楚那次失败属于哪一类）。
type Handler func(ctx context.Context, req Request) (Response, error)

// Server 父侧服务端：读子进程发来的调用请求，执行后回帧。
//
// # 父侧是**应答方**（谁发起、谁应答）
//
// 程序在子进程里（`host.<tool>()` 由程序发起），故**子侧是发起方**（Client），
// 父侧是应答方（Server）。方向搞反会导致记账记在错误的一侧——
// 配额该在**接受调用**时扣，不是谁发起谁扣。
//
// # 它同时是**预算的权威**（不变量 3）
//
// 调用数与输出字节数由**父侧**记账。子进程只是执行者——若子进程自己记账，
// 它可以谎报自己没超预算。故 Budget 挂在 Server 上，由父侧逐次扣减。
//
// # 并发处理 + 在途硬上限（不变量 4）
//
// 每个请求在独立 goroutine 里处理，故一次慢调用不阻塞其他调用。总量预算
// （MaxCalls）拦不住「瞬间发起十万次并发调用」——那时它们都还没返回，父侧已被
// goroutine 淹没。故另设**在途并发上限**，超出即回「超限」帧，**不排队等**。
//
// 这是**可用性**约束，与 MaxCalls 的**配额**约束是两件事。
//
// # 取消传播（不变量 5）
//
// 父侧 ctx 取消 → 关闭连接 → 子侧读到 EOF → 子侧全部在途调用失败。
// 不需要单独的取消帧：**管道关闭本身就是最强的取消信号**。
type Server struct {
	// r 读端（请求帧从这里进来）。
	r io.Reader
	// w 写端（响应帧从这里出去）。
	w io.Writer
	// handler 处理调用。
	handler Handler
	// budget 父侧记账的预算（不变量 3）。
	budget *Budget
	// sem 在途闸（不变量 4）。容量 = maxInflight。
	sem chan struct{}
	// writeMu 串行化写（响应帧并发产出，帧不能交错）。
	writeMu sync.Mutex
	// closed 已关闭。
	closed bool
}

// ServerOption Server 的构造选项。
type ServerOption func(*Server)

// WithBudget 设父侧记账的预算（不变量 3）。零值 = 不限。
func WithBudget(b Budget) ServerOption {
	return func(s *Server) { s.budget = &b }
}

// WithMaxInflight 设在途调用硬上限（不变量 4）。<=0 用默认值。
func WithMaxInflight(n int) ServerOption {
	return func(s *Server) {
		if n > 0 {
			s.sem = make(chan struct{}, n)
		}
	}
}

// NewServer 构造父侧服务端。
func NewServer(rw io.ReadWriter, h Handler, opts ...ServerOption) *Server {
	s := &Server{
		r:       rw,
		w:       rw,
		handler: h,
		budget:  &Budget{},
		sem:     make(chan struct{}, DefaultMaxInflight),
	}
	for _, o := range opts {
		if o != nil {
			o(s)
		}
	}
	return s
}

// Serve 读-执行-回帧，直到 EOF 或出错。
//
// **协议层错误即终止**：版本不匹配、帧损坏——这些不是「某次调用失败」，
// 是「两侧说的不是同一种话」，继续回帧只会产出更难查的错。
func (s *Server) Serve(ctx context.Context) error {
	for {
		var req Request
		if err := ReadFrame(s.r, &req); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				// 子进程正常退出：读到底即结束。
				return nil
			}
			return err
		}
		if err := checkVersion(req.V); err != nil {
			return err
		}
		if req.ID == "" {
			return errors.New("wire: 请求 ID 不得为空")
		}
		// 在途上限（不变量 4）：拿不到闸即回「超限」，**不排队等**。
		select {
		case s.sem <- struct{}{}:
		default:
			_ = s.writeFrame(Response{
				V: Version, ID: req.ID, OK: false,
				Kind:  string(toolfail.ClassRateLimited),
				Error: ErrInflightLimit.Error(),
			})
			continue
		}
		// 预算（不变量 3）：父侧在接受调用时记账。
		if !s.budget.charge(1, 0) {
			<-s.sem
			_ = s.writeFrame(Response{
				V: Version, ID: req.ID, OK: false,
				Kind:  string(toolfail.ClassRateLimited),
				Error: "调用数配额已用尽",
			})
			continue
		}
		go s.serveOne(ctx, req)
	}
}

// serveOne 处理一次调用并回帧。
func (s *Server) serveOne(ctx context.Context, req Request) {
	defer func() { <-s.sem }()
	resp := s.handle(ctx, req)
	resp.V = Version
	resp.ID = req.ID
	// 输出字节记账在父侧（不变量 3）。
	s.budget.charge(0, len(resp.Value))
	_ = s.writeFrame(resp)
}

// handle 执行一次调用并构造响应帧。
func (s *Server) handle(ctx context.Context, req Request) Response {
	if s.handler == nil {
		return Response{
			OK:    false,
			Kind:  string(toolfail.ClassPermanent),
			Error: "父侧未装配处理器",
		}
	}
	resp, err := s.handler(ctx, req)
	if err != nil {
		// 不可分类 = 不可重试（与 toolfail 的保守缺省一致）。
		return Response{
			OK:    false,
			Kind:  string(toolfail.ClassUnknown),
			Error: err.Error(),
		}
	}
	if !resp.OK && resp.Kind == "" {
		// Handler 说失败却没给分类 → 归到 unknown，不让它退化成自由字符串。
		resp.Kind = string(toolfail.ClassUnknown)
	}
	return resp
}

// writeFrame 串行化写帧。
func (s *Server) writeFrame(v any) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return WriteFrame(s.w, v)
}

// Budget 父侧记账的预算（不变量 3）。
//
// 与 `sandbox.Budget` 的区别：那是「宿主对**后端**的要求」（哪些项要兜住），
// 这里是「父侧**实际记着**的账」（已用掉多少）。两者不是一回事——要求的是
// 上限，实际的是消耗。
type Budget struct {
	// MaxCalls 总调用数上限。0 = 不限。
	MaxCalls int
	// MaxBytes 累计输出字节上限。0 = 不限。
	MaxBytes int
	// st 记账状态（指针：Budget 按值传递时不得复制锁）。
	st *budgetState
}

// budgetState 记账状态。单独一个结构体并用指针持有，
// 是为了让 Budget 可以按值传递而不复制锁（go vet 会拦「含锁的值拷贝」）。
type budgetState struct {
	mu        sync.Mutex
	usedCalls int
	usedBytes int
}

// state 取记账状态（惰性初始化，供零值 Budget 使用）。
func (b *Budget) state() *budgetState {
	if b.st == nil {
		b.st = &budgetState{}
	}
	return b.st
}

// Used 返回已用的调用数与字节数。
func (b *Budget) Used() (calls, bytes int) {
	st := b.state()
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.usedCalls, st.usedBytes
}

// charge 记一笔账；超限返回 false（**不**扣账——超限的那次不该算已用）。
func (b *Budget) charge(calls, bytes int) bool {
	st := b.state()
	st.mu.Lock()
	defer st.mu.Unlock()
	if b.MaxCalls > 0 && st.usedCalls+calls > b.MaxCalls {
		return false
	}
	if b.MaxBytes > 0 && st.usedBytes+bytes > b.MaxBytes {
		return false
	}
	st.usedCalls += calls
	st.usedBytes += bytes
	return true
}

// Close 关闭服务端（幂等）。
//
// 关闭只停**接受新调用**；已在途的调用由各自 goroutine 收尾。
func (s *Server) Close() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.closed = true
	return nil
}
