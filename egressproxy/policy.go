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
	"sort"
	"strconv"
	"strings"

	"github.com/oekit/pkg/errors"
)

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
func (p Policy) Permit(host string, port int) error {
	h := normalizeHost(host)
	if h == "" {
		return &BlockedError{Host: host, Port: port, Reason: "目标主机为空"}
	}
	if matchAny(p.DenyHosts, h) {
		return &BlockedError{Host: h, Port: port, Reason: "命中拒绝名单"}
	}
	if len(p.AllowHosts) == 0 {
		return &BlockedError{Host: h, Port: port, Reason: "放行名单为空（默认拒绝）"}
	}
	if !matchAny(p.AllowHosts, h) {
		return &BlockedError{Host: h, Port: port, Reason: "不在放行名单内"}
	}
	if !p.portAllowed(port) {
		return &BlockedError{Host: h, Port: port, Reason: "端口不在放行端口内"}
	}
	return nil
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

// net_JoinHostPort 只在本文件用一次（避免为一行拼装引 net 包的其余名字）。
func net_JoinHostPort(host string, port int) string {
	return host + ":" + strconv.Itoa(port)
}
