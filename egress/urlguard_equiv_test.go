package egress

import (
	"testing"

	"github.com/oekit/pkg/urlguard"
)

// 本文件钉 guardx#118 的验收判据：同一批 URL 语料跑 egress 与 oekit/pkg/urlguard
// 两套判定，**结论必须一致**——不一致的条目要么修（修不了的进「已知差异」表，
// 并写明理由）。判定表双维护的分叉风险由此守门：任一侧段表改动导致结论漂移，
// CI 即红。
//
// 比对层：两边都是**字面量层** URL 校验（egress.Check vs urlguard.CheckURL，
// 缺省放行面 = 只放公网）。urlguard 的解析层判定在 DialFunc（拨号层），
// egress 的是 CheckResolving——层形态不同，不在本语料比对范围。
//
// 段表比对发现的既有分叉已在 egress 侧补齐：::/96（IPv4-compatible）与
// fec0::/10（site-local）——见 ipv6SpecialUse 的注释。

// corpusEntry wantEgress / wantGuard 记的是**实际钉住**的结论（blocked=true）。
// 两边结论不一致的条目必须写 diffWhy（进已知差异表的凭据，缺了测试就红）。
type corpusEntry struct {
	url        string
	wantEgress bool
	wantGuard  bool
	diffWhy    string
}

// urlguardCorpus 字面量层语料：两套判定的禁止段口径（私网/回环/链路本地/
// 云元数据/CGNAT/special-use IPv6/exotic IPv4 字面量/scheme 白名单/userinfo
// 逃逸）在缺省放行面下逐条对齐。
var urlguardCorpus = []corpusEntry{
	// ── 回环 ──
	{"http://127.0.0.1/", true, true, ""},
	{"http://127.0.0.1:8080/", true, true, ""},
	{"http://127.0.0.1./", true, true, ""}, // FQDN 尾点归一后仍是回环
	{"http://[::1]/", true, true, ""},
	{"http://[::1%25lo]/", true, true, ""}, // zone 只决定网卡，不改变地址
	{"http://[::]/", true, true, ""},       // 未指定地址
	{"http://localhost/", true, true, ""},
	{"http://api.localhost/", true, true, ""}, // localhost 域含子域
	{"http://LOCALHOST/", true, true, ""},     // 大小写不敏感

	// ── 私网 / CGNAT / 链路本地（含云元数据）──
	{"http://10.0.0.5/", true, true, ""},
	{"http://172.16.0.9/", true, true, ""},
	{"http://192.168.1.9/", true, true, ""},
	{"http://169.254.169.254/latest/meta-data/", true, true, ""}, // 云元数据
	{"http://100.64.0.1/", true, true, ""},                       // CGNAT
	{"http://[fd00::1]/", true, true, ""},                        // ULA
	{"http://[fe80::1]/", true, true, ""},                        // v6 链路本地

	// ── 保留段 / 文档段 / 组播 ──
	{"http://0.0.0.0/", true, true, ""},
	{"http://0.1.2.3/", true, true, ""}, // 0.0.0.0/8 整段（不只全零地址）
	{"http://192.0.0.9/", true, true, ""},
	{"http://192.0.2.1/", true, true, ""},
	{"http://198.51.100.7/", true, true, ""},
	{"http://203.0.113.9/", true, true, ""},
	{"http://198.18.0.1/", true, true, ""},
	{"http://224.0.0.1/", true, true, ""},
	{"http://240.0.0.1/", true, true, ""},
	{"http://255.255.255.255/", true, true, ""},

	// ── IPv6 special-use 与载体逃逸 ──
	{"http://[::ffff:127.0.0.1]/", true, true, ""}, // 4in6 载体
	{"http://[::ffff:10.0.0.1]/", true, true, ""},
	{"http://[::7f00:1]/", true, true, ""},        // ::/96 IPv4-compatible（#118 补齐）
	{"http://[fec0::5]/", true, true, ""},         // site-local（#118 补齐）
	{"http://[64:ff9b::7f00:1]/", true, true, ""}, // NAT64 内嵌回环
	{"http://[64:ff9b:1::5]/", true, true, ""},    // NAT64 local-use
	{"http://[2002::7f00:1]/", true, true, ""},    // 6to4 内嵌回环
	{"http://[2001::7f00:1]/", true, true, ""},    // Teredo 内嵌回环
	{"http://[2001:db8::1]/", true, true, ""},     // 文档段
	{"http://[2001:2::1]/", true, true, ""},       // benchmark
	{"http://[2001:10::1]/", true, true, ""},      // ORCHID
	{"http://[2001:20::1]/", true, true, ""},      // ORCHID2
	{"http://[100::1]/", true, true, ""},          // discard-only

	// ── exotic IPv4 字面量（宽松解析器会当地址）──
	{"http://0177.0.0.1/", true, true, ""},
	{"http://127.1/", true, true, ""},
	{"http://0x7f000001/", true, true, ""},
	{"http://0x7f.0.0.1/", true, true, ""},
	{"http://2130706433/", true, true, ""},
	{"http://1.2.3/", true, true, ""}, // 短形态（inet_aton 末段补齐）
	{"http://0/", true, true, ""},

	// ── scheme 白名单 / userinfo 逃逸 / 空 host ──
	{"file:///etc/passwd", true, true, ""},
	{"ftp://example.com/", true, true, ""},
	{"ws://example.com/", true, true, ""},
	{"http://user@127.0.0.1/", true, true, ""}, // userinfo 不参与 host 判定
	{"http:///path", true, true, ""},           // 空 host fail-closed

	// ── 公网目标照常放行（两边同一结论）──
	{"http://example.com/", false, false, ""},
	{"http://api.example.com/deep/path", false, false, ""},
	{"http://EXAMPLE.COM/", false, false, ""},
	{"http://example.com./", false, false, ""},
	{"http://93.184.216.34/", false, false, ""},
	{"http://1.2.3.4:8080/", false, false, ""},
	{"http://[2606:4700::1111]/", false, false, ""},
	{"http://[::ffff:93.184.216.34]/", false, false, ""}, // mapped 公网
	{"http://user@93.184.216.34/", false, false, ""},
	{"http://beef.ca/", false, false, ""}, // 含字母段的域名形态（非 exotic）

	// ── 已知差异（判定语义刻意不同，非段表漂移；diffWhy 是表的凭据）──
	{"http://api.internal/", false, true,
		"urlguard 阻断 .internal 约定后缀；egress 字面量层放行域名（域名=零 DNS 防护是本包明示边界，解析层 CheckResolving 对解析不出/解析到私网 fail-closed）"},
	{"http://api.local/", false, true,
		"同上：.local 后缀 urlguard 阻断、egress 字面量层放行"},
	{"http://api.localdomain/", false, true,
		"同上：.localdomain 后缀 urlguard 阻断、egress 字面量层放行"},
	{"http://127。0。0。1/", false, true,
		"urlguard 做确定性折叠（U+3002 → .）后判回环；egress 词法守卫不含非 ASCII 折叠，按域名放行（解析层 fail-closed 兜底）"},
	{"http://中文.com/", false, true,
		"urlguard 对折叠不掉的非 ASCII host fail-closed；egress 字面量层放行域名（IDN 由调用方先做 punycode）"},
	{"http://999.999.999.999/", true, false,
		"四段纯十进制超范围：egress 按全数字段 exotic fail-closed 拒绝；urlguard 的 parseIPv4Part 无范围检查、四段全十进制不算 exotic，落到域名路径放行（该形态 inet_aton 也解不出，实际连不上）"},
}

// TestURLGuardVerdictEquivalence 同一语料跑两套判定（#118 验收判据：
// 结论一致；不一致的条目必须写明 diffWhy 进已知差异表）。
func TestURLGuardVerdictEquivalence(t *testing.T) {
	g, err := urlguard.New()
	if err != nil {
		t.Fatal(err)
	}
	for _, ce := range urlguardCorpus {
		egressBlocked := Check(ce.url) != nil
		guardBlocked := g.CheckURL(ce.url) != nil
		if egressBlocked != ce.wantEgress {
			t.Errorf("egress(%q) = %v，钉住结论 %v", ce.url, egressBlocked, ce.wantEgress)
		}
		if guardBlocked != ce.wantGuard {
			t.Errorf("urlguard(%q) = %v，钉住结论 %v", ce.url, guardBlocked, ce.wantGuard)
		}
		if egressBlocked != guardBlocked && ce.diffWhy == "" {
			t.Errorf("两套判定对 %q 结论不同（egress=%v urlguard=%v）却未登记已知差异（diffWhy 为空）", ce.url, egressBlocked, guardBlocked)
		}
	}
}

// TestURLGuardCorpusKnownDiffs Documented 已知差异表不允许静默消失或扩容：
// 上表里结论相异的条目集合必须与 diffWhy 非空的条目集合**一一对应**——
// urlguard 侧演进（或本仓补齐语义）让某条一致了，测试提示把该条移入一致区；
// 反向新增分叉而不写理由，测试直接红。
func TestURLGuardCorpusKnownDiffsDocumented(t *testing.T) {
	g, err := urlguard.New()
	if err != nil {
		t.Fatal(err)
	}
	for _, ce := range urlguardCorpus {
		egressBlocked := Check(ce.url) != nil
		guardBlocked := g.CheckURL(ce.url) != nil
		differ := egressBlocked != guardBlocked
		if differ && ce.diffWhy == "" {
			t.Errorf("%q 出现未登记的分叉（egress=%v urlguard=%v）：要么修齐，要么写 diffWhy", ce.url, egressBlocked, guardBlocked)
		}
		if !differ && ce.diffWhy != "" {
			t.Errorf("%q 已一致（egress=%v urlguard=%v）：把它移进一致区，并更新 diffWhy 说明的语义前提", ce.url, egressBlocked, guardBlocked)
		}
	}
}
