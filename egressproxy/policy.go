// Package egressproxy 进程级出口强制：一个只监听回环的本地 HTTP 代理
// （含 `CONNECT` 隧道），作为「声明了受限出口」的**兑现件**。
//
// # 它补的是哪个洞
//
// 子进程（以及宿主起的 curl / git / 各种 native 工具）的出站流量在编排进程的
// 任何 Go 层守卫之外：`HTTP_PROXY` 只是一组环境变量，子进程可以忽略它。
// 于是「声明了受限出口」与「实际能出网」之间没有任何东西——直到有一个**真的
// 在中间拦着**的代理，并且子进程只能经它出去。
//
// 两层缺一不可：
//
//   - 代理（本包）：真的拦、真的拒、默认拒绝；
//   - 环境下发（agent-harness 的 `egress.Spec.Env`）：把子进程指过来。
//
// 只有其中一层都等于没有：代理没人用是装饰，env 没人拦是空话。
//
// # 边界
//
//   - **只监听回环**（`127.0.0.1:0`），不对外提供服务；
//   - 只做**目标准入**（主机 + 端口 + 只读方法），不看内容——`CONNECT` 之后是
//     TLS，看不到任何字节，这一点在 `Limited` 的文档里写清，不假装能看见；
//   - 不认识任何业务概念：白/黑名单由调用方给，本包只判。
package egressproxy

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/oagentkit/guardx/egress"
	"github.com/oekit/pkg/errors"
)

// Resolver 域名解析的最小接口（guardx#96 DNS 围栏的注入点）：*net.Resolver
// 天然满足，测试与特殊网络环境注入 stub 也只需要实现这一个方法。
// （与 egress.Resolver 同形——本包的解析围栏复用 egress.CheckHostResolving，
// 两个接口结构等价，同一个值两边都能传。）
type Resolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

// Policy 代理的放行面。
//
// **默认拒绝**：`AllowHosts` 为空 ⇒ 任何目标都不放行（不是「不限」）。
// 这条缺省与 permgate / sandbox 的口径一致——沉默按最弱处理，
// 「没配置」绝不能被读成「放行」。
type Policy struct {
	// AllowHosts 允许的目标主机：精确主机名，或通配后缀 "*.example.com"。
	//
	// 通配语义**只匹配子域**：`*.example.com` 命中 `a.example.com` 与
	// `a.b.example.com`，**不**命中 `example.com`（要它请显式写一条），
	// 也**不**命中 `evilexample.com`（后缀按标签边界比，不做裸后缀比较）。
	// 单独一个 "*" 表示放行全部主机（此时 `DenyHosts` 仍然优先）——
	// 这是「只做黑名单」的唯一写法，必须显式写出来。
	//
	// ⚠️ 对**域名**条目（guardx#96）：命中名单只是第一道闸——本放行面
	// 缺省会解析 DNS，并把**全部解析结果**逐个过 IP 围栏（私网/链路本地/
	// 云元数据等一律拒绝，解析失败/空结果 fail-closed）。组织 DNS（或被
	// 劫持的内网 DNS）把名单里的域名解析到内网的借道形态由此被挡住。
	//
	// ⚠️ 对 **IP 字面量**条目（guardx#119）：逐字写进名单（如 "127.0.0.1"）
	// 才是调用方对这个地址的**显式意图**，返回自身供拨号钉住、不走解析；
	// 通配命中（"*" 或 "*.x"）只说明「没写任何地址/没写这个地址」，**不构成**
	// 显式意图——此时字面量照样过 IP 围栏（黑名单模式下 169.254.169.254 /
	// 127.0.0.1 一类不放行）。同一个地址换个写法结论相反的形态不被允许
	// （#96 修复说明：同仓两个包对「域名→IP」这一步的治理必须同一套）。
	AllowHosts []string
	// DenyHosts 拒绝的目标主机（语义同 AllowHosts，**优先于** AllowHosts）。
	DenyHosts []string
	// AllowPorts 允许的目标端口。空 ⇒ 只允许 443 与 80。
	//
	// 为什么空缺省不是「全部端口」：代理最常见的失手是「主机名单对了，
	// 但放行了 22 或 3306」——端口是攻击面的一部分，必须显式开。
	AllowPorts []int
	// Limited 只读模式：**明文**请求只允许 GET / HEAD。
	//
	// ⚠️ 对 `CONNECT` 不生效且无法生效：CONNECT 之后是 TLS（或任意协议），
	// 方法不可见。所以 Limited 对 HTTPS 只保证「目标主机在名单内」，
	// 不保证「只读」——这是能力的真实边界，写在这里而不是留给使用者猜。
	Limited bool
	// Resolver 域名解析器（guardx#96 DNS 围栏）。nil = net.DefaultResolver。
	// 测试与特殊网络环境（内部 DNS、hosts 覆盖）从这里注入。
	Resolver Resolver
	// SkipDNSCheck 显式关闭 DNS 围栏（guardx#96）：只按主机名判定，
	// 不解析、返回零地址（调用方按主机名拨号）。
	//
	// ⚠️ 这是对「解析到内网的域名照转」**解防**的显式开关——只该在宿主
	// 明确接受「域名=零 DNS 防护」的轻量档使用（与 egress 包对裸 CheckHost
	// 的警示同一口径）。缺省必须是解析 + fail-closed。
	//
	// 豁免范围（guardx#119 收敛）：跳过的只是**域名解析**——IP 字面量与
	// exotic IPv4 词法形态（0177.0.0.1 一类）的**字面量层判定不豁免**
	// （前者照常过 IP 围栏并返回已检地址，后者照常拒绝）：那些判定不是
	// 解析判定，地址写法本身的危险不随「不解析」消失。
	SkipDNSCheck bool
}

// BlockedError 准入拒绝（结构化：调用方按需呈现原因与目标）。
type BlockedError struct {
	Host   string
	Port   int
	Reason string
}

func (e *BlockedError) Error() string {
	return "egressproxy: 拒绝 " + net_JoinHostPort(e.Host, e.Port) + "：" + e.Reason
}

// Validate 自检放行面本身是否可用（写错即报错，不静默按空名单跑）。
func (p Policy) Validate() error {
	for _, h := range p.AllowHosts {
		if err := validateHostPattern(h); err != nil {
			return errors.Wrap(err, "egressproxy: AllowHosts 非法")
		}
	}
	for _, h := range p.DenyHosts {
		if err := validateHostPattern(h); err != nil {
			return errors.Wrap(err, "egressproxy: DenyHosts 非法")
		}
	}
	for _, port := range p.AllowPorts {
		if port < 1 || port > 65535 {
			return errors.Errorf("egressproxy: AllowPorts 含非法端口 %d（合法 1-65535）", port)
		}
	}
	return nil
}

func validateHostPattern(h string) error {
	s := strings.TrimSpace(h)
	if s == "" {
		return errors.New("空条目")
	}
	if s == "*" {
		return nil
	}
	if strings.HasPrefix(s, "*.") {
		if len(s) <= 2 {
			return errors.Errorf("通配条目 %q 没有后缀", h)
		}
		if strings.ContainsAny(s[2:], "*?") {
			return errors.Errorf("通配条目 %q 只支持前置 \"*.\"，不支持中间通配", h)
		}
		return nil
	}
	if strings.ContainsAny(s, "*?") {
		return errors.Errorf("通配条目 %q 只支持前置 \"*.\"", h)
	}
	return nil
}

// Permit 判一个目标是否放行。拒绝一律返回 *BlockedError。
//
// ⚠️ 域名目标（guardx#96）：命中名单后还会**解析 DNS** 并把全部解析结果
// 逐个过 IP 围栏（缺省 fail-closed）——只判主机名字符串的旧形态正是
// egress#60 同款洞在代理层的复现。需要已检地址做拨号钉住的调用方请用
// PermitResolving；本方法是其丢弃地址的便捷形态。
func (p Policy) Permit(host string, port int) error {
	_, err := p.PermitResolving(context.Background(), host, port)
	return err
}

// PermitResolving 判一个目标是否放行，并返回**已过检的地址集合**。
// 拒绝一律返回 *BlockedError。
//
// # 判定顺序
//
//  1. 名单判定（与既有口径一致）：空主机 / 命中拒绝名单 / 放行名单为空 /
//     不在放行名单内 / 端口未放行——先于一切 DNS 查询，未过的目标不触发
//     解析（fail-fast，也不给任意域名当解析器用）；
//  2. IP 字面量 host（netip 可解析的）：**逐字**命中名单才是显式意图，
//     返回该地址本身，不触发解析（guardx#119）；通配命中（"*" / "*.x"）
//     不构成显式意图——字面量照样过 IP 围栏（字面量无解析步骤，本步与
//     SkipDNSCheck 无关：那个开关关的是「域名解析」，不是「地址本身的
//     IP 判定」）；
//  3. DNS 围栏（guardx#96）：域名 host 经 Resolver（nil 时
//     net.DefaultResolver）解析，**全部解析结果**逐个过与 egress 同一套
//     IP 围栏（egress.Policy 零值：私网/回环/链路本地（含云元数据）/CGNAT/
//     组播/保留段一律拒绝，只放公网）；解析失败、解析结果为空、解析出
//     判定不了的地址都 fail-closed。exotic IPv4 词法形态（127.1 /
//     0x7f000001——inet_aton 语义会被 cgo resolver 解析成回环）在词法层
//     直接拒绝——这一条**不受 SkipDNSCheck 豁免**（它不是解析判定，
//     是字面量词法判定；SkipDNSCheck=true 时同样执行）。
//
// # 返回值与 TOCTOU
//
// 返回的地址集合是**已全部过检**的：调用方（本包代理的两条转发路径）拨号
// 时钉住其中之一（字面量直连，不再二次解析），才能闭合「检查后换解析」
// 的 TOCTOU——egress#60 修复说明明确了「返回全部已检地址供拨号钉住是闭合
// check/use 间 TOCTOU 的前提」，CONNECT 隧道（长连接，TOCTOU 窗口更大）
// 尤其需要钉住。SkipDNSCheck 为 true 时返回 (nil, nil)：无已检地址，调用方
// 按主机名拨号（IP 字面量除外——见第 2 步，字面量照常返回已检地址）。
func (p Policy) PermitResolving(ctx context.Context, host string, port int) ([]netip.Addr, error) {
	h := normalizeHost(host)
	if h == "" {
		return nil, &BlockedError{Host: host, Port: port, Reason: "目标主机为空"}
	}
	if matchAny(p.DenyHosts, h) {
		return nil, &BlockedError{Host: h, Port: port, Reason: "命中拒绝名单"}
	}
	if len(p.AllowHosts) == 0 {
		return nil, &BlockedError{Host: h, Port: port, Reason: "放行名单为空（默认拒绝）"}
	}
	if !matchAny(p.AllowHosts, h) {
		return nil, &BlockedError{Host: h, Port: port, Reason: "不在放行名单内"}
	}
	if !p.portAllowed(port) {
		return nil, &BlockedError{Host: h, Port: port, Reason: "端口不在放行端口内"}
	}
	// IP 字面量（guardx#119）：逐字命中名单 = 调用方确实写了这个地址
	// （显式意图），返回自身供拨号钉住；通配命中（"*" / "*.x"）只是
	// 「没写任何地址」，落到 IP 围栏——169.254.169.254 / 127.0.0.1 一类
	// 在黑名单模式下不放行。这一步在 SkipDNSCheck 之前：字面量判定不是
	// DNS 判定，不被「跳过解析」豁免。
	// 返回前 Unmap()（guardx#123）：IPv4-mapped IPv6 字面量（::ffff:x.x.x.x）
	// 的 netip 形态 Is4In6，String() 仍是 ::ffff: 前缀形态——而拨号面
	// pinnedDial 的 Control 复核按 Unmap().String() 比对（net 栈 Control 收到
	// 的也是点分 v4 形态）。不归一的话集合建在 mapped 形态、比对在裸 v4
	// 形态，两侧恒不相等 ⇒ 已检地址 100% 被自己的钉住复核拒掉（合法配置
	// 自我失能）。非 mapped 地址 Unmap 是恒等，纯 v6/v4 字面量不受影响。
	if addr, err := netip.ParseAddr(h); err == nil {
		if matchExact(p.AllowHosts, h) {
			return []netip.Addr{addr.Unmap()}, nil
		}
		addrs, err := egress.CheckHostResolving(ctx, h, egress.Policy{}, p.resolver())
		if err != nil {
			return nil, &BlockedError{Host: h, Port: port, Reason: "IP 围栏（通配命中不豁免，fail-closed）: " + err.Error()}
		}
		for i := range addrs {
			addrs[i] = addrs[i].Unmap()
		}
		return addrs, nil
	}
	if p.SkipDNSCheck {
		// 显式跳过的是**域名解析**；字面量层判定不在豁免范围——exotic IPv4
		// 词法形态（0177.0.0.1 / 0x7f000001 / 127.1）会被宽松解析器
		// （inet_aton 语义）解析成回环，属词法判定而非解析判定，与判定
		// 文档一致照常执行（egress.CheckHost 对这类形态 fail-closed，
		// 对普通域名放行——跳过解析正是本开关的语义）。IP 字面量已在
		// 上一分支全部过围栏，走不到这里。
		if err := egress.CheckHostWith(h, egress.Policy{}); err != nil {
			return nil, &BlockedError{Host: h, Port: port, Reason: "字面量围栏（exotic IPv4 词法形态不受 SkipDNSCheck 豁免）: " + err.Error()}
		}
		return nil, nil
	}
	// DNS 围栏（guardx#96）：复用 egress.CheckHostResolving——同仓两个包对
	// 「域名→IP」这一步的治理必须同一套，egress.Policy 零值 = 只放公网
	// （代理的威胁主体是宿主子进程，借道名单摸内网/云元数据正是要挡的）。
	addrs, err := egress.CheckHostResolving(ctx, h, egress.Policy{}, p.resolver())
	if err != nil {
		return nil, &BlockedError{Host: h, Port: port, Reason: "DNS 围栏（解析结果须全过 IP 策略，fail-closed）: " + err.Error()}
	}
	// 归一 v4-in-v6 载体（net.ParseIP 对 v4 一律给 16 字节）：钉住的字面量
	// 用裸 v4 形态拨号（93.184.216.34），不是 ::ffff: 前缀形态——同一地址，
	// 拨号面干净。
	for i := range addrs {
		addrs[i] = addrs[i].Unmap()
	}
	return addrs, nil
}

// resolver 取注入的解析器；nil 交由 egress.CheckHostResolving 落到
// net.DefaultResolver。
func (p Policy) resolver() egress.Resolver {
	if p.Resolver == nil {
		return nil
	}
	return p.Resolver
}

func (p Policy) portAllowed(port int) bool {
	if len(p.AllowPorts) == 0 {
		return port == 80 || port == 443
	}
	for _, x := range p.AllowPorts {
		if x == port {
			return true
		}
	}
	return false
}

// Ports 返回落到生效值的端口清单（空 ⇒ 80/443），顺序确定。
func (p Policy) Ports() []int {
	if len(p.AllowPorts) == 0 {
		return []int{80, 443}
	}
	out := append([]int(nil), p.AllowPorts...)
	sort.Ints(out)
	return out
}

func normalizeHost(h string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
}

// matchAny 按标签边界比对主机模式。
func matchAny(patterns []string, host string) bool {
	for _, raw := range patterns {
		pat := normalizeHost(raw)
		switch {
		case pat == "*":
			return true
		case pat == host:
			return true
		case strings.HasPrefix(pat, "*."):
			// 只匹配子域：host 必须以 "."+suffix 结尾，且前面至少有一个标签。
			suffix := pat[1:] // ".example.com"
			if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
				return true
			}
		}
	}
	return false
}

// matchExact 判 host 是否被**逐字**写进名单（归一后全等比较）。
//
// 与 matchAny 的差别只在通配："*" 与 "*.suffix" 的命中不算逐字——通配命中
// 只说明「没写任何地址 / 没写这个地址」，不构成对某个具体地址的显式意图
// （guardx#119：IP 字面量的「名单即意图」豁免只认逐字命中）。
func matchExact(patterns []string, host string) bool {
	for _, raw := range patterns {
		if normalizeHost(raw) == host {
			return true
		}
	}
	return false
}

// net_JoinHostPort 错误消息里的 host:port 拼装（IPv6 host 带回括号）。
func net_JoinHostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}
