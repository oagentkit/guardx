// extnames_test.go —— 宿主扩展位（精确名单 + 后缀名单）的登记面与判定面。
//
// 从 netguard_test.go 拆出：扩展位是**一套独立的登记面**（宿主可注入的名单），
// 与「默认名单」「名字层判定」「URL 判定」是三件事。拆分的理由是**判据的一侧**——
// 「扩展位怎么登记、登记错了会怎样」与「默认名单怎么判」不共享同一批断言。
package netguard

import (
	"fmt"
	"sync"
	"testing"

	"github.com/oekit/pkg/errors"
)

// TestExtraBlockedNamesCannotDisableDefaults 扩展表与默认名单并集生效，
// 只能加不能减：宿主把扩展表改写成无关内容，也摘不掉默认名单。
func TestExtraBlockedNamesCannotDisableDefaults(t *testing.T) {
	defer func() {
		SetExtraBlockedHostnames()
		_ = SetExtraBlockedHostSuffixes()
	}()
	SetExtraBlockedHostnames("extra-blocked.example")
	if err := SetExtraBlockedHostSuffixes(".blocked-example"); err != nil {
		t.Fatalf("合法后缀不应被拒: %v", err)
	}

	if err := CheckURLWith("http://extra-blocked.example/x", Allow{Private: false, Loopback: false}); !errors.Is(err, ErrBlockedName) {
		t.Errorf("扩展精确名单应生效，实得 %v", err)
	}
	if err := CheckURLWith("http://a.blocked-example/x", Allow{Private: false, Loopback: false}); !errors.Is(err, ErrBlockedName) {
		t.Errorf("扩展后缀名单应生效，实得 %v", err)
	}
	// 默认名单一个都不能少。断言同样落在 ErrBlockedName 上：
	// 只看「有错」的话，扩展表被改成可覆盖默认时不一定暴露得出来。
	for _, u := range []string{
		"http://metadata.google.internal/x", "http://metadata.goog/x",
		"http://host.docker.internal/x", "http://gateway.docker.internal/x",
		"http://svc.internal/x", "http://printer.local/x", "http://svc.localdomain/x",
		"http://box.lan/x",
	} {
		if err := CheckURLWith(u, Allow{Private: false, Loopback: false}); !errors.Is(err, ErrBlockedName) {
			t.Errorf("%s: 扩展表不应能摘掉默认名单项，实得 %v", u, err)
		}
	}
}

// TestExtraSuffixNormalizedOnInjection 后缀大小写/空白在**注入期**归一，
// 匹配侧只做 HasSuffix、不做任何清洗。
//
// `.CORP` 曾经**永不匹配**——挂着一个看着在拦、实际不拦的后缀，且没有任何信号。
// 对拦截名单来说这是最坏的失败模式：失效方向是「放行」，不是「误拦」。
func TestExtraSuffixNormalizedOnInjection(t *testing.T) {
	defer func() { _ = SetExtraBlockedHostSuffixes() }()
	if err := SetExtraBlockedHostSuffixes("  .CORP  ", "\t.Corp-Internal\n"); err != nil {
		t.Fatalf("合法后缀不应被拒: %v", err)
	}
	// 命中类断言走 CheckURL：这些名字在名字层就被拒，走不到解析，无 DNS 依赖。
	for _, u := range []string{
		"http://a.corp/x", "http://A.CORP/x", "http://svc.corp-internal/x",
	} {
		if err := CheckURLWith(u, Allow{Private: false, Loopback: false}); !errors.Is(err, ErrBlockedName) {
			t.Errorf("%s: 归一化后应命中扩展后缀，实得 %v", u, err)
		}
	}
	// 反向断言走 checkHostName：未命中意味着还要继续解析，CheckURL 会真去查 DNS。
	// 这里要验的只是「后缀没有退化成子串/前缀匹配」，不必付网络的代价。
	for _, h := range []string{"corp.example.com", "notcorp-internal.example.com", "corp"} {
		if err := checkHostName(h, false); err != nil {
			t.Errorf("主机名 %q 不应被后缀命中（后缀不等于子串），实得 %v", h, err)
		}
	}
}

// TestExtraSuffixDotlessRejected 无前导点的后缀在**注入处**拒绝，不静默收下。
//
// 为什么拒绝而不是自动补点：默认表里每个后缀都带点，因为 `internal` 是顶级域，
// 不该因为 `foo.internal` 被拦就整片拒掉。`corp` 照单全收会把语义从「拦 foo.corp」
// 悄悄变成「拦一切以 corp 结尾的名字」——那比不拦更糟，误伤面不可预测。
// 同理拒绝归一化后永不匹配的写法（裸 `.` / 带尾点）：主机名判定前已去尾点，
// 这类后缀进去了也一条都拦不到，属同一类静默失效。
//
// 拒绝必须发生在调用点：等到匹配时才发现，这次注册早已悄悄放行了。
func TestExtraSuffixDotlessRejected(t *testing.T) {
	for _, bad := range []string{"corp", "", "   ", ".", ".corp.", "\tCORP\n", "corp "} {
		err := SetExtraBlockedHostSuffixes(bad)
		if !errors.Is(err, ErrInvalidBlockedSuffix) {
			t.Errorf("后缀 %q 应在注入处被拒（ErrInvalidBlockedSuffix），实得 %v", bad, err)
		}
	}
}

// TestExtraSuffixRejectionKeepsPrevious 校验不过就整批不装，旧名单原样保留。
// 半套名单比旧名单更难推理：调用方以为注册成功了，日后却查不出哪几条在拦。
func TestExtraSuffixRejectionKeepsPrevious(t *testing.T) {
	defer func() { _ = SetExtraBlockedHostSuffixes() }()
	if err := SetExtraBlockedHostSuffixes(".keep-example"); err != nil {
		t.Fatalf("前置注册失败: %v", err)
	}
	if err := SetExtraBlockedHostSuffixes(".good-example", "nodot"); !errors.Is(err, ErrInvalidBlockedSuffix) {
		t.Fatalf("含非法项的批次应整批被拒，实得 %v", err)
	}
	if err := CheckURLWith("http://a.good-example/x", Allow{Private: false, Loopback: false}); err == nil {
		t.Error("被拒批次里的合法项不应被部分安装")
	}
	if err := CheckURLWith("http://a.keep-example/x", Allow{Private: false, Loopback: false}); !errors.Is(err, ErrBlockedName) {
		t.Errorf("被拒批次不应动到上一份名单，实得 %v", err)
	}
}

// TestExtraHostnamesNormalizedOnInjection 精确名单与判定侧同用 normalizeHost
// （小写 + 去尾点），调用方不必自己保证大小写；空白项直接丢弃。
func TestExtraHostnamesNormalizedOnInjection(t *testing.T) {
	defer SetExtraBlockedHostnames()
	SetExtraBlockedHostnames("  Blocked.Example.  ", "exact-example", "", "   ")
	for _, h := range []string{"blocked.example", "BLOCKED.EXAMPLE.", "exact-example"} {
		if err := checkHostName(h, false); !errors.Is(err, ErrBlockedName) {
			t.Errorf("主机名 %q 归一化后应命中，实得 %v", h, err)
		}
	}
	if err := checkHostName("other-example", false); err != nil {
		t.Errorf("未注册名不应被拦，实得 %v", err)
	}
}

// TestExtraBlockedConcurrentSetAndClassify 并发注册 + 并发判定的竞态钉子。
//
// 扩展位曾是导出 `var`：注册（写）与 classifyHostName（读）并发即数据竞争，而
// map 的并发读写是 **fatal runtime error，recover 抓不住**——不是 panic，是进程直接没。
// 非 -race 下它大概率「看起来能跑」，所以这条断言只在 -race 下有意义；
// 但它必须长期留在库里，否则扩展位下次被人改回导出变量时没有网。
//
// 判定结果本身故意不断言：名单一直在换，任一时刻的结论都是合法的。要验的是
// 「并发下不崩、不竞争」。
func TestExtraBlockedConcurrentSetAndClassify(t *testing.T) {
	defer func() {
		SetExtraBlockedHostnames()
		_ = SetExtraBlockedHostSuffixes()
	}()
	const iterations = 200
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				SetExtraBlockedHostnames(fmt.Sprintf("blocked-%d.example", i))
				_ = SetExtraBlockedHostSuffixes(fmt.Sprintf(".blocked-%d.example", i))
			}
		}()
	}
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				_, _, _ = classifyHostName(fmt.Sprintf("host-%d.example", i))
				_ = checkHostName(fmt.Sprintf("host-%d.internal", i), false)
			}
		}()
	}
	wg.Wait()
}
