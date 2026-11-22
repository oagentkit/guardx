package netguard

import (
	"testing"

	"github.com/oekit/pkg/urlguard"
)

// 本文件钉住「本包与 oekit/pkg/urlguard 的域名后缀判定」之间的关系——与 egress
// 侧的 urlguard_equiv_test.go 同款守门：**两份判定表并存且有意不同，不是同一份
// 真相的两个副本**，因此断言的是**已知差异集**，而不是「两侧结论相同」。
//
// 差异的由来（两侧语义本就不同，不是谁漏了谁）：
//
//   - 本包：非公网命名空间后缀**带前导点号**（.internal）⇒ 只拦 foo.internal，
//     顶级域 internal 本身不整片拒（那是个合法 TLD）；另加 .lan——局域网约定域，
//     不是 RFC 保留段。
//   - urlguard：后缀**不带点号**，且 host == suffix 也命中 ⇒ 顶级域 internal
//     整片拒；名单里不含 .lan。
//
// 为什么要钉：两侧各自增删后缀时，任一侧的改动都会让本用例红 ⇒ 差异从「靠人
// 记得比对」变成机器守门。钉住的差异集也顺带把「谁是哪份表的权威」写进了代码：
// 禁止段口径见 egress 侧等价性用例，域名后缀差异见本文件。
func TestURLGuardDomainSuffixParity(t *testing.T) {
	g, err := urlguard.New()
	if err != nil {
		t.Fatalf("urlguard.New: %v", err)
	}

	cases := []struct {
		host          string
		netguardBlock bool
		urlguardBlock bool
		why           string
	}{
		{"foo.internal", true, true, "两侧同拒：非公网命名空间"},
		{"foo.localdomain", true, true, "两侧同拒：非公网命名空间"},
		{"foo.local", true, true, "两侧同拒：非公网命名空间"},
		{"foo.localhost", true, true, "两侧同拒：回环族名字"},
		{"internal", false, true, "差异：顶级域本身——urlguard 整片拒，本包只拒带前缀的"},
		{"localdomain", false, true, "差异：顶级域本身——urlguard 整片拒，本包只拒带前缀的"},
		{"foo.lan", true, false, "差异：.lan 是局域网约定域（RFC 保留段之外），本包拒、urlguard 不管"},
		{"example.com", false, false, "两侧同放行：普通公网域"},
	}

	for _, c := range cases {
		blocked, _, _ := classifyHostName(c.host)
		if blocked != c.netguardBlock {
			t.Errorf("netguard 判定 %q = %v，期望 %v（%s）", c.host, blocked, c.netguardBlock, c.why)
		}
		ugBlocked := g.CheckHost(c.host) != nil
		if ugBlocked != c.urlguardBlock {
			t.Errorf("urlguard 判定 %q = %v，期望 %v（%s）", c.host, ugBlocked, c.urlguardBlock, c.why)
		}
	}
}
