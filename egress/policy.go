package egress

// Policy 放行面（**具名值**）。
//
// # 为什么要有这个类型
//
// Options 的两个 bool 位**读不出意图**：同样的 {AllowPrivate: true, AllowLoopback: false}
// 在不同调用点可能表达不同场景（内网自建服务 / 回调地址 / 探测本机），
// 而值一旦传岔，就会出两种故障：
//
//   - 校验层放行私网、拨号层按缺省拒 ⇒ 假红（「配置明明允许内网，调用却失败」）；
//   - 校验层拒、拨号层放行 ⇒ **安全问题**（写面拒了，拨号层没拒）。
//
// Policy 把放行面收成**一个值**：写面校验（Check / CheckHost）与拨号层守卫
// （NewClient / MustClient）都从同一个值派生 ⇒ **结构上没法不一致**。
//
// # 与 Options 的关系
//
// Policy 是本体，Options 是**旧名的兼容别名**（同一个类型，不是两套表示）：
// 既有的 egress.Options{AllowPrivate: true} / egress.Options{} 调用点照旧编译，
// 语义逐字相同。新代码请用 Policy 与下面的具名放行面。
//
// # 零值口径
//
// 零值 = 两个放行位全关 = 只放公网与域名（与 Check / CheckHost 的缺省口径一致），
// 即 PublicOnly。
type Policy struct {
	// AllowPrivate 放行私网段（IPv4 RFC1918 / IPv6 唯一本地）。
	AllowPrivate bool
	// AllowLoopback 放行回环与未指定地址（仅 127.0.0.0/8、::1、0.0.0.0、::
	// 四个字面量）。0.0.0.0/8 余下整段是 RFC 1122 的 "this network" 保留段，
	// 与 CGNAT/benchmark 同列——不在放行面内。
	AllowLoopback bool
}

// Options 旧名（兼容别名）。
//
// 已由 Policy 取代：Policy 是本体，Options 只是旧名——保留它是为了让既有调用点
// 继续编译（egress.Options{AllowPrivate: true} 与 egress.Options{} 都照旧可用），
// 语义与 Policy 完全一致（**同一个类型**，不是两套并行表示）。
//
// 新代码请用 Policy + 具名放行面（PublicOnly / PrivateNoLoopback / SelfService）。
type Options = Policy

// 具名放行面（常用组合）。
//
// ⚠️ 这些是**包级变量**：可以读，但**不要重新赋值**——改它们等于全局改掉所有
// 消费方的放行面（Policy 是值类型，要变体时自己构造副本：
//
//	p := egress.PrivateNoLoopback
//	p.AllowLoopback = true
//
// ).
var (
	// PublicOnly 只放公网（目标完全由用户填的场景）——零值口径。
	PublicOnly = Policy{}
	// PrivateNoLoopback 放行私网、拒回环（内网自建服务是合法场景）。
	PrivateNoLoopback = Policy{AllowPrivate: true}
	// SelfService 私网与回环都放行（探测本机自建服务）。
	SelfService = Policy{AllowPrivate: true, AllowLoopback: true}
)

// Check 校验完整 URL 的 host（放行面 = 本值；解析失败 fail-closed）。
//
// 与 CheckWith 等价——同一个值派生，语义不可能与写面分叉。
func (p Policy) Check(rawURL string) error {
	return CheckWith(rawURL, p)
}

// CheckHost 校验 host（放行面 = 本值；空值 fail-closed；非 IP 字面量放行）。
//
// 与 CheckHostWith 等价——同一个值派生，语义不可能与写面分叉。
func (p Policy) CheckHost(host string) error {
	return CheckHostWith(host, p)
}
