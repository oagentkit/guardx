package sandbox

// Capable 可选能力面：后端能否兑现这组预算。
//
// # 为什么是**可选接口**而不是 Provider 的新方法
//
// Provider 已在 v0.9.0 发布，给它加方法是**破坏性变更**——已实现它的宿主
// 全部编译不过。可选接口则让既有实现**编译期零改动**：
//
//	不实现 Capable ⇒ 只兑现基本三闸、**不兑现内存**
//	⇒ 要求 MaxMemory 的请求不被选中 ⇒ fail closed。
//
// 缺省语义天然落在**保守的一侧**——漏声明的后端拿到的是「兜不住」，
// 不是「兜得住」。方向与安全语义一致：漏声明 ⇒ 少能力，不是多豁免。
//
// # 判定的是「整组」而非「逐项」
//
// Supports(b) 一次问完「这组预算我兜不兜得住」。逐项判定（SupportsMemory 之类）
// 更细，但接口会随预算项增长而变大，且**逐项判定会让后端各自拼装「哪些项算
// 兜住了」的规则**——那份规则会漂移。整组判定把它留在后端一处（它最清楚
// 自己兜不兜得住），登记簿只问一次。
//
// # 「不支持」与「选中后失败」不是一回事
//
// 兜不住的后端**不被选中**（见 Registry.Resolve），不是选中后执行失败。
// 差别在于：前者是**装配期**的判定（宿主还没跑任何东西就知道这个环境
// 满足不了要求），后者要等到执行时才暴露。
type Capable interface {
	// Supports 报告该后端能否兑现 b 这组预算。
	//
	// 返回 false 意味着：要求了 b 里的某些项，而该后端兜不住那些项。
	// 零值 Budget（全零）**恒应返回 true**——没要求任何东西就没什么兜不住。
	Supports(b Budget) bool
}

// CapableFunc 把一个普通函数适配成 Capable。
//
// 让后端不必为一行判定写一个具名类型：
//
//	type myProvider struct{…}
//
//	func (myProvider) Supports(b sandbox.Budget) bool {
//	    return b.MaxMemory <= 0 // 进程内后端兜不住内存
//	}
//
// 或更省事：
//
//	type myProvider struct{…}
//
//	func (myProvider) Supports(b sandbox.Budget) bool { return sandbox.SupportsBasic(b) }
type CapableFunc func(b Budget) bool

// Supports 实现 Capable。
func (f CapableFunc) Supports(b Budget) bool { return f(b) }

// SupportsBasic 是一个 Capable：只兑现基本三闸（墙钟 / 调用数 / 输出字节），
// **不兑现内存**。
//
// 进程内解释器后端用它——Go 运行时没有「只给一个 VM 限内存」的开关，
// 解释器本身也没有内存限制 API，故这类后端**如实**只能兑现三闸。
//
// 零值 Budget（无要求）返回 true：没要求内存，就不存在「兜不住内存」。
func SupportsBasic(b Budget) bool { return b.MaxMemory <= 0 }

// SupportsAll 是一个 Capable：兑现全部预算项（含内存）。
//
// 只有**真能**兜住内存的后端（子进程 + 内核 rlimit 之类）才能用它。
// 用它之前先确认兑现是真的——档位表与支持面都是后端自报的，本包不校验其真实性。
func SupportsAll(Budget) bool { return true }
