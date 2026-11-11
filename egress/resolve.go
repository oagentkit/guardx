package egress

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"

	"github.com/oekit/pkg/errors"
)

// Resolver 域名解析的最小接口：*net.Resolver 天然满足，测试与特殊网络
// 环境注入 stub 也只需要实现这一个方法。
type Resolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

// CheckResolving 校验完整 URL，域名解析后**全部解析结果逐个过 IP 策略**。
//
// 这是 LLM 可控 URL 场景应使用的入口：Check 系列对域名不解析，私网/云元数据/
// CGNAT 等 IP 策略可被「解析到内网的域名」（如 169.254.169.254.nip.io）全量
// 绕过，也没有任何 DNS-rebinding 防护。
//
// 语义（全链路 fail-closed）：
//   - scheme 必须 http/https（与 Check 同一白名单）；
//   - IP 字面量 host 走与 CheckHost 相同的字面量判定，返回该地址本身；
//   - 域名 host 经 r（nil 时用 net.DefaultResolver）解析，**任何一条**解析
//     结果命中策略即阻断；解析失败、解析结果为空同样阻断——「解析不出来」
//     与「解析到禁止 IP」都是不可放行的未知，放行任何一个都是把围栏的
//     判定权交给网络环境；
//   - 返回值是**已全部过检**的地址集合：调用方拨号时钉住其中之一
//     （而非重新解析），才能闭合「检查后换解析」的 TOCTOU。
//
// 注意：放行≠承诺之后的解析不变。攻击者控制权威 DNS 时可在检查与拨号之间
// 换答案（DNS rebinding）——拨号侧用返回的地址钉住，或叠加 Policy.NewClient
// 的拨号层守卫，二者至少取一。
func CheckResolving(ctx context.Context, rawURL string, p Policy, r Resolver) ([]netip.Addr, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("egress: URL 解析失败: %w", err)
	}
	if err := checkScheme(u); err != nil {
		return nil, err
	}
	return CheckHostResolving(ctx, u.Hostname(), p, r)
}

// CheckHostResolving 校验 host，域名解析后全部结果逐个过 IP 策略
// （语义与 fail-closed 口径见 CheckResolving）。
func CheckHostResolving(ctx context.Context, host string, p Policy, r Resolver) ([]netip.Addr, error) {
	h := normalizeHost(host)
	if h == "" {
		return nil, fmt.Errorf("egress: 空 host")
	}
	if isLocalhostDomain(h) && !p.AllowLoopback {
		// localhost 域即回环的域形态：拒绝路径不必解析（答案恒是回环），
		// 放行路径（AllowLoopback）与普通域名一样走解析，口径单一份。
		return nil, &BlockedError{Host: h, Reason: "localhost 域"}
	}
	if addr, err := netip.ParseAddr(h); err == nil {
		// IP 字面量：与 CheckHost 同一字面量判定，返回归一后地址供拨号钉住。
		effective, reason := addrPolicy(addr, p)
		if reason != "" {
			return nil, &BlockedError{Host: h, Addr: effective.String(), Reason: reason}
		}
		return []netip.Addr{effective}, nil
	} else if looksLikeExoticIPv4(h) {
		// 与 checkHost 同一 exotic 词法守卫：这些形态进 resolver 会被
		// inet_aton 语义解析成内网地址，必须在词法层就 fail-closed。
		return nil, &BlockedError{Host: h, Reason: "exotic IPv4 字面量形态"}
	}

	if r == nil {
		r = net.DefaultResolver
	}
	ips, err := r.LookupIP(ctx, "ip", h)
	if err != nil {
		return nil, errors.Wrap(err, "egress: 域名解析失败（fail-closed）: "+h)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("egress: 域名解析结果为空（fail-closed）: %s", h)
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			// 非法长度不属于任何合法解析结果——按解析出「判不出来的地址」
			// fail-closed，而不是跳过（跳过 = 假装没看见）。
			return nil, fmt.Errorf("egress: 域名 %s 解析出无法判定的地址 %v", h, ip)
		}
		effective, reason := addrPolicy(addr, p)
		if reason != "" {
			return nil, &BlockedError{Host: h, Addr: effective.String(), Reason: reason}
		}
		out = append(out, addr)
	}
	return out, nil
}
