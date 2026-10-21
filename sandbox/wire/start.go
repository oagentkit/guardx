package wire

import (
	"fmt"
	"time"
)

// Start 父侧 → 子侧：启动一次执行。
//
// # 为什么它与 Request 是两类帧
//
// Request 是「子侧向父侧要一次工具调用」，Start 是「父侧告诉子侧跑什么」。
// 两者层次不同：一次执行里可能有**零到很多**次工具调用。
//
// 混在一类帧里的代价是「帧的含义要靠上下文猜」——那是最难查的一类协议 bug。
// 故分成两个类型，各自有明确的发起方向。
type Start struct {
	// V 协议版本。
	V int `json:"v"`
	// Program 被执行的程序体。
	//
	// **由后端自己解释**（不变量：内核不规定程序语言）——子侧知道这段程序
	// 对自己意味着什么（脚本？DSL？），父侧只负责把它送到。
	Program string `json:"program"`
	// Bindings 程序可用的绑定清单。
	//
	// 父侧把绑定**清单**（名字与调用形态）交给子侧，而不是把绑定**实现**交出去
	// ——实现留在父侧，子侧通过工具调用帧请求执行。这正是跨进程的意义：
	// 宿主工具只在宿主进程里存在。
	Bindings []StartBinding `json:"bindings"`
	// Budget 这次执行的要求（父侧对后端的要求）。
	//
	// 与父侧记账用的 Budget 不同：那是「实际记着多少」，这是「要求多少」。
	Budget StartBudget `json:"budget"`
	// ResultID 本次执行的结果标识（子侧回报结果时带回）。
	ResultID string `json:"result_id"`
}

// StartBinding 绑定清单项：名字与调用形态。
//
// **不含实现**——实现留在父侧（子侧通过工具调用帧请求执行）。
type StartBinding struct {
	// Name 工具名（父侧的原始名）。
	Name string `json:"name"`
	// Signature JS 调用形态，如 "get_logs(host, count)"。
	//
	// 空 = 退化为 `host.<name>(argsJSON)`。
	Signature string `json:"signature,omitempty"`
}

// StartBudget 父侧对这次执行的要求。
type StartBudget struct {
	// WallClock 墙钟期限。
	WallClock time.Duration `json:"wall_clock,omitempty"`
	// MaxCalls 调用数上限。
	MaxCalls int `json:"max_calls,omitempty"`
	// MaxBytes 输出字节上限。
	MaxBytes int `json:"max_bytes,omitempty"`
	// MaxMemory 内存上限（字节）。0 = 不要求。
	//
	// 子侧**兜不住**这一项时应当拒绝（而不是假装兜住了）——这与
	// `sandbox.Capable` 的缺省语义同源：漏声明得到的是「兜不住」。
	MaxMemory int64 `json:"max_memory,omitempty"`
}

// Result 子侧 → 父侧：一次执行的结果。
//
// 与 Response 的区别：Response 是一次**工具调用**的结果，Result 是**整次执行**
// 的结果（程序跑完了没有、跑了什么、错在哪）。
type Result struct {
	// V 协议版本。
	V int `json:"v"`
	// ResultID 对应 Start.ResultID。
	ResultID string `json:"result_id"`
	// OK 执行是否成功。
	OK bool `json:"ok"`
	// Value 成功时的结果文本（编码由后端定）。
	Value string `json:"value,omitempty"`
	// Kind 失败时的分类（**toolfail.Class**，不变量 2）。
	Kind string `json:"kind,omitempty"`
	// Error 失败时的可读原因（给人看，不参与判定）。
	Error string `json:"error,omitempty"`
	// Calls 本次执行实际发起的工具调用次数（父侧用于对账）。
	Calls int `json:"calls,omitempty"`
	// Bytes 本次执行实际产生的输出字节数（父侧用于对账）。
	Bytes int `json:"bytes,omitempty"`
}

// checkStart 校验 Start 帧的必要字段。
func checkStart(s *Start) error {
	if s.ResultID == "" {
		return fmt.Errorf("wire: Start 帧缺少 result_id")
	}
	return nil
}

// checkResult 校验 Result 帧的必要字段。
func checkResult(r *Result) error {
	if r.ResultID == "" {
		return fmt.Errorf("wire: Result 帧缺少 result_id")
	}
	return nil
}
