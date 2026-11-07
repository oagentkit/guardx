package sandbox

// EgressMode 出站策略档位（值越大越严）。
//
// # 它补的是本包哪一格
//
// 本包管「程序在哪跑、跑起来能触达什么」。「在哪跑」是 Level，「资源兜得住
// 哪几项」是 Capable，而「能触达哪些目标」此前**没有任何可声明的位置**——
// 于是「声明了受限出口」在执行后端这一侧没有对照物：宿主写了一档要求，
// 没有任何东西能回答「这个后端做不做得到」。
//
// # 三档为什么这样排序
//
//	EgressUnrestricted(0) < EgressProxy(1) < EgressDenied(2)
//
// 「禁网」严格强于「经代理」：禁网的后端天然满足「经代理」的要求（没有流量
// 能出），反之不成立。排序让「后端能力 ≥ 要求」可以用一个整数比较表达，
// 不需要枚举矩阵。
//
// # 为什么词表必须在 tier 0 的这一层
//
// 同一份设计里还有一个「后端能力声明」接口 EgressEnforcer{ Egress() EgressMode }。
// Go 的接口一致性要求**返回值类型同一**：词表若留在下游（例如此前它只存在于
// agent-harness 的 egress 包里），上游任何执行后端要实现那个接口都得 import
// 下游 —— 而下游依赖本仓，于是成环。
//
// 后果不是「写起来别扭」，是**接口在结构上只可能由宿主实现**：「上游提供一个
// 能兑现的后端」这条路被类型系统堵死，而且堵得毫无声响——编译期不报错，只是
// 永远没有人能满足它。实测代价是一整条出口声明链（声明面 / 判据 / 环境下发
// 全齐）空转了一轮：没有任何后端能声明「我能兑现」。
//
// 故词表与契约放在这里，与 Level 同层同理：跨模块共享的**词表**必须低于所有
// 实现方。
type EgressMode int

const (
	// EgressUnrestricted 不要求（默认；零值即此档，故旧调用点行为不变）。
	EgressUnrestricted EgressMode = iota
	// EgressProxy 要求出站经代理（可配合白名单做目标限制）。
	EgressProxy
	// EgressDenied 要求完全禁网（只能由执行后端强制，环境变量做不到）。
	EgressDenied
)

// String 词面（审计与错误文案用；与 policy 里的档位名一致）。
func (m EgressMode) String() string {
	switch m {
	case EgressUnrestricted:
		return "unrestricted"
	case EgressProxy:
		return "proxy"
	case EgressDenied:
		return "denied"
	default:
		return "unknown"
	}
}

// Satisfies 判本档是否满足 required（本档 ≥ required）。
func (m EgressMode) Satisfies(required EgressMode) bool { return m >= required }

// Valid 报告档位是否在词表内（越界值不得被当成「不限制」——那是沉默放行）。
func (m EgressMode) Valid() bool { return m >= EgressUnrestricted && m <= EgressDenied }

// EgressEnforcer 由执行后端（或强制代理）声明：它能兑现哪个出站档位。
//
// # 「能兑现」是什么意思
//
// 后端说的不是「我期望这一档」，而是「我能**强制**这一档」：
//
//   - EgressProxy：所有出站流量**确实**只能经它指定的代理出去
//     （例如本地 HTTP/SOCKS5 代理 + 子进程环境指向它——两者缺一不可）；
//   - EgressDenied：所有出站流量**确实**被阻断（内核级或网络命名空间级），
//     而不是「设了一组看起来很严的环境变量」。
//
// # 为什么是可选接口而不是 Provider 的必选方法
//
// 改必选方法就是跨仓破坏性变更（Provider 的三个方法要被所有既有实现补齐），
// 而本包只需要「能问就问，问不到即拒绝」——fail-closed 的判定不依赖上游改造。
//
// # 为什么判定不在本包
//
// 本包是 tier 0，不认识任何调用方，也不该替调用方决定「没声明算不算满足」——
// 那是个策略问题，且答案必须保守（沉默 = 不满足）。判定在消费方：
// agent-harness 的 egress.Spec.SatisfiedBy 把「沉默」按最弱处理。
type EgressEnforcer interface {
	// Egress 返回该后端实际能兑现的档位。
	Egress() EgressMode
}
