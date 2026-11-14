package wire

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

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
// # 单次调用期限由父侧执行（#78）
//
// Request.DeadlineMS 是子侧的声明，**父侧执行**：handler 收到的 ctx 带期限，
// 期限到父侧直接回类型化失败帧（kind=transient），不等 handler。子侧声明只能
// 把期限**调短**：超过宿主上限（WithMaxCallDeadline）按上限执行。
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
	// maxCallDeadline 宿主自设的单次调用期限上限（#78）。0 = 不设。
	//
	// 子侧声明的 DeadlineMS 只能把期限**调短**不能调长——父侧是记账与取消的
	// 权威（不变量 3/5），不能被子侧一句大数掀翻。
	maxCallDeadline time.Duration
	// closer 底层连接（实现 io.Closer 时）。Close() 用它停收：关连接解除
	// 阻塞中的 ReadFrame，Serve 随之干净退出（#80）。
	closer io.Closer
	// closedFlag 停收标志（Close 置位，Serve 逐帧检查）。
	closedFlag atomic.Bool
	// closeOnce 保证 Close 幂等且只关一次连接。
	closeOnce sync.Once
	// writeMu 串行化写（响应帧并发产出，帧不能交错）。
	writeMu sync.Mutex
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

// WithMaxCallDeadline 设宿主侧的单次调用期限上限（#78）。
//
// 这是父侧对子侧声明（Request.DeadlineMS）的**钳制**：声明比它长按它执行，
// 不声明也按它执行（父侧必须自己兜住，子进程说了不算）；声明比它短则按声明
// （子侧只能把期限调短，不能调长）。<=0 = 不设上限（只执行子侧声明）。
func WithMaxCallDeadline(d time.Duration) ServerOption {
	return func(s *Server) {
		if d > 0 {
			s.maxCallDeadline = d
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
	// 记下可关的底层连接：Close() 停收靠它解除阻塞中的读（#80）。
	if c, ok := rw.(io.Closer); ok {
		s.closer = c
	}
	for _, o := range opts {
		if o != nil {
			o(s)
		}
	}
	return s
}

// Serve 读-执行-回帧，直到 EOF、Close 或出错。
//
// **协议层错误即终止**：版本不匹配、帧损坏——这些不是「某次调用失败」，
// 是「两侧说的不是同一种话」，继续回帧只会产出更难查的错。
//
// Close() 停收（#80）：停收标志置位后不再受理新请求；若底层连接可关，
// Close 已顺带关了它，阻塞中的读被解除，本循环干净返回 nil。
func (s *Server) Serve(ctx context.Context) error {
	for {
		if s.isClosed() {
			// Close() 停收：不再受理任何新调用。
			return nil
		}
		var req Request
		if err := ReadFrame(s.r, &req); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				// 子进程正常退出：读到底即结束。
				return nil
			}
			if s.isClosed() {
				// Close() 关连接触发的读错误是正常停机，不是协议故障。
				return nil
			}
			return err
		}
		if s.isClosed() {
			// 与 Close 并发竞态里读到的最后一帧也不受理。
			return nil
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
		goSafe(func() { s.serveOne(ctx, req) })
	}
}

// serveOne 处理一次调用并回帧。
func (s *Server) serveOne(ctx context.Context, req Request) {
	defer func() { <-s.sem }()
	er := s.execute(ctx, req)
	if er.written {
		// 期限路径已就地回帧（见 execute），这里只负责还闸。
		return
	}
	resp := er.resp
	resp.V = Version
	resp.ID = req.ID
	// 输出字节记账在父侧（不变量 3）；超限即拒付整帧（#80）——既不静默整投
	// （那是字节面失守），也不悄悄截断（截断会让子侧误以为拿到了完整结果）。
	// Error 与 Value 同为响应的输出面（guardx#185）：失败帧携带的可读原因
	// （err.Error() 可内嵌工具输出片段、单帧上限 16MB）此前不入账——巨型
	// Error 反复返回即可绕开 MaxBytes 预算持续推给子进程，charge 的
	// 「超限拒付整帧」在 Error 面从未生效。两段一并记账。
	if !s.budget.charge(0, len(resp.Value)+len(resp.Error)) {
		_ = s.writeFrame(Response{
			V: Version, ID: req.ID, OK: false,
			Kind:  string(toolfail.ClassRateLimited),
			Error: "输出字节配额已用尽",
		})
		return
	}
	_ = s.writeFrame(resp)
}

// execResult 一次调用的执行产物。
type execResult struct {
	// resp handler 产出的响应（written=true 时为零值）。
	resp Response
	// written 响应已在 execute 内回帧（期限到路径），serveOne 不必再写。
	written bool
}

// callDeadline 算这次调用的父侧执行期限（#78）。
//
// 取子侧声明（DeadlineMS）与宿主上限（WithMaxCallDeadline）的**较小者**：
// 声明超上限按上限（子侧只能调短不能调长），没声明但设了上限也按上限
// （父侧必须自己兜住）。两者都没有 = 0 = 不限期。
func (s *Server) callDeadline(req Request) time.Duration {
	var d time.Duration
	if req.DeadlineMS > 0 {
		d = time.Duration(req.DeadlineMS) * time.Millisecond
	}
	if s.maxCallDeadline > 0 && (d <= 0 || d > s.maxCallDeadline) {
		d = s.maxCallDeadline
	}
	return d
}

// execute 在期限约束下执行一次调用（#78）。
//
// 期限到即回**类型化失败帧**（kind=transient——toolfail 把超时归瞬时故障），
// 不等 handler 返回——期限一到，结果对子侧已无意义；handler 是否理会 ctx 是
// 宿主的事，父侧不把「兜住期限」寄托在 handler 自觉上。
//
// 但在途闸要等 handler goroutine 退出才还：否则失控子进程可以用
// 「声明短期限 + 挂死 handler」绕过在途上限无限刷 goroutine。挂死的 handler
// 占住名额与修前行为一致（占住即拒绝新调用），进程级兜底（WallClock/杀进程）
// 仍在它之上。
func (s *Server) execute(ctx context.Context, req Request) execResult {
	d := s.callDeadline(req)
	if d <= 0 {
		return execResult{resp: s.handle(ctx, req)}
	}
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, d)
	defer cancel()

	done := make(chan Response, 1)
	goSafe(func() {
		// panic 也要喂满 done：否则期限分支的 <-done 会永久吊死一个名额。
		defer func() {
			if r := recover(); r != nil {
				done <- Response{
					OK:    false,
					Kind:  string(toolfail.ClassUnknown),
					Error: fmt.Sprintf("handler panic: %v", r),
				}
			}
		}()
		done <- s.handle(ctx, req)
	})

	select {
	case resp := <-done:
		return execResult{resp: resp}
	case <-ctx.Done():
		// 响亮、有类型：期限到/被取消都回失败帧，绝不静默吞掉在途调用。
		resp := Response{
			V:    Version,
			ID:   req.ID,
			OK:   false,
			Kind: string(toolfail.ClassTransient),
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			resp.Error = fmt.Sprintf("调用期限已到（父侧执行，声明 DeadlineMS=%d）: %v", req.DeadlineMS, ctx.Err())
		} else {
			resp.Error = fmt.Sprintf("调用被父侧取消: %v", ctx.Err())
		}
		// 超时/取消回帧同为出站字节，先入账再回帧（guardx#188）：本路径此前
		// writeFrame 直写、未经 charge——「所有出站字节必记账」的不变量多了
		// 一个未登记例外。文案今天由父侧固定生成（不含对端可控内容），但
		// 不变量不该靠文案善良好使——后续谁往里拼对端回显，账必须在。
		// 与 serveOne 同一 charge 口径（Value/Error 两段之和）；超限拒付整帧，
		// 回与 serveOne 同款「输出字节配额已用尽」帧（拒付帧本身不入账——
		// charge 已拒绝，无账可记，父侧固定文案）。
		if !s.budget.charge(0, len(resp.Value)+len(resp.Error)) {
			_ = s.writeFrame(Response{
				V: Version, ID: req.ID, OK: false,
				Kind:  string(toolfail.ClassRateLimited),
				Error: "输出字节配额已用尽",
			})
		} else {
			_ = s.writeFrame(resp)
		}
		<-done // 等 handler goroutine 退出（ctx 已取消，规范 handler 会退；不退的占住名额，见上）。
		return execResult{written: true}
	}
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
	// MaxBytes 累计输出字节上限。0 = 不限。记账面是响应的 Value 与 Error
	// 两段之和（guardx#185：失败帧的可读原因同样是推给子进程的字节）。
	MaxBytes int
	// st 记账状态。**只经 state() 的原子原语读写**（裸指针保持 Budget 可按值
	// 传递不复制锁；st 指针本身的并发惰性建经 CAS 同步，见 state）。
	st *budgetState
}

// budgetState 记账状态。单独一个结构体并用指针持有，
// 是为了让 Budget 可以按值传递而不复制锁（go vet 会拦「含锁的值拷贝」）。
type budgetState struct {
	mu        sync.Mutex
	usedCalls int
	usedBytes int
}

// state 取记账状态（**并发安全**惰性初始化，供零值 Budget 使用）。
// 此前是无锁 check-then-act（oagentkit/guardx#143）：并发首笔两个 goroutine
// 各建一个 budgetState 并写回——b.st 是 data race（-race 必红），且记账分裂
// 到两个 state、usedCalls 各自少算，MaxCalls=N 实放约 2N，父侧预算权威
// （「子进程说了不算」）被并发击穿。CAS 保证只建一份，败者共用先建者的
// state。budgetState 自带的 mu 只护计数，护不到懒建本身。
// atomic.Value 无 LoadOrStore、atomic.Pointer 带 noCopy 会破坏 Budget 的按值
// 传递语义，故对指针字段直接上 atomic 原语（经典 CAS 惰建形态）。
func (b *Budget) state() *budgetState {
	for {
		st := (*budgetState)(atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&b.st))))
		if st != nil {
			return st
		}
		fresh := &budgetState{}
		if atomic.CompareAndSwapPointer((*unsafe.Pointer)(unsafe.Pointer(&b.st)), nil, unsafe.Pointer(fresh)) {
			return fresh
		}
	}
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

// Close 关闭服务端（幂等，#80 接线）。
//
// 「关闭只停接受新调用」由此真正落地：
//   - 置停收标志：Serve 循环逐帧检查，不再受理新请求；
//   - 关底层连接（若实现 io.Closer）：解除阻塞中的读，Serve 干净返回 nil；
//     子侧随即读到 EOF，其在途调用全部失败（不变量 5——管道关闭就是取消信号）。
//
// 已在途的调用仍由各自 goroutine 收尾（向已关连接回帧会失败、被忽略）。
// 底层不实现 io.Closer 时标志立即生效，但阻塞中的那次读要等连接自然断开。
func (s *Server) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.closedFlag.Store(true)
		if s.closer != nil {
			// 关连接解除阻塞中的读；由此触发的读写错误是停机的一部分。
			err = s.closer.Close()
		}
	})
	return err
}

// isClosed 报告是否已停收。
func (s *Server) isClosed() bool { return s.closedFlag.Load() }
