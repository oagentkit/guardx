package sandbox

import (
	"context"
	"time"
)

// Provider 一个执行后端。
//
// # 后端自己解释 Request
//
// Process 读作程序源码（进程内解释器后端），外部进程后端读作可执行路径。
// **本包不规定程序语言**——宿主知道自己的工具面长什么样，本包不该替它定。
//
// # 谁实现 Provider
//
// 常见的一种实现是「进程内解释器」后端（隔离档位 LevelProcess）；更强的后端
// （内核级、硬件虚拟化）由宿主实现并注册：它们要么需要宿主自己的运行环境，
// 要么牵涉宿主的部署形态，都是**宿主的事**。本包只认协议，不认实现。
type Provider interface {
	// ID 后端标识，在登记簿里唯一。
	ID() string
	// Level 该后端提供的隔离档位。
	Level() Level
	// Exec 执行一次程序。
	Exec(ctx context.Context, req Request) (Outcome, error)
}

// Request 一次执行请求。
type Request struct {
	// Program 后端可解释的程序体（语义由后端定，见 Provider 注释）。
	Program string
	// Args 位置参数（后端可忽略）。
	Args []string
	// Dir 工作目录（后端可忽略）。
	Dir string
	// Budget 资源预算（后端按自身能力解释；不支持的项忽略）。
	Budget Budget
}

// Budget 资源预算：墙钟 / 调用次数 / 输出字节数 / 内存上限。
//
// 墙钟与调用数是所有后端都该兜住的（失控的程序会一直跑、一直调）；
// 输出字节数是可选的（后端能截断就截断，不能就忽略）。
//
// 本包**不强制任何后端实现全部几项**——后端不支持的项忽略即可；「这项没兜住」
// 是后端自己的能力声明，宿主据此判断，不在这里假装统一。
//
// # 「兜不住」怎么表达：Capable
//
// 后端能兜住哪些项，由它实现 Capable 自报（见 capable.go）。**不实现 Capable
// 的后端只兑现基本三闸、不兑现内存**——于是「要求了内存兜底而后端兜不住」
// 这件事有了信号：登记簿不会选中它（见 Registry.Resolve）。
type Budget struct {
	WallClock time.Duration
	MaxCalls  int
	MaxBytes  int
	// MaxMemory 内存上限（字节）。0 = 不要求。
	//
	// 进程内后端**兜不住**这一项：Go 运行时没有「只给一个 VM 限内存」的开关，
	// 解释器本身也没有内存限制 API。要真正兜住它只能把执行搬出宿主进程。
	// 故要求它的宿主会拿到明确拒绝（该后端不被选中），而不是「以为兜住了、
	// 实际没有」。
	MaxMemory int64
}

// Outcome 一次执行的结果。
type Outcome struct {
	// OK 是否成功。
	OK bool
	// Value 成功时的结果文本（编码由后端定）。
	Value string
	// Err 失败原因（成功时为 nil）。
	Err error
	// Detail 后端私有明细。
	//
	// 跨包的通用结果装不下后端特有的结构（出错位置、调用清单、失败分类…），
	// 而本包不认识任何后端的内部结构，故由后端自行附带、调用方按类型断言取用。
	//
	// 约定：Detail **不得**成为任何可判定事实的第二份真相——档位与成败一律以
	// 本包的字段为准，Detail 只是明细。两份真相迟早会漂移，那时没人知道该信哪份。
	Detail any
}

// Failure 执行失败：Kind 是后端的分类串，Message 是可读原因。
//
// 为什么不让后端直接塞一个 error：跨包通用结果需要一个**稳定**的失败形状，
// 否则调用方只能按类型断言逐个后端认，而每认一个就多一处会漂移的分支。
// Kind 是分类（可判定），Message 是给人看的（不可判定）。
type Failure struct {
	Kind    string
	Message string
}

// Error 实现 error。
func (e *Failure) Error() string { return e.Message }
