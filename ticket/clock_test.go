// clock_test.go —— issue #186 契约判据：过期判定的时间真相只有存储一个。
//
// 旧实现的 Take/GC 收调用方给的 now，多副本下「谁的时钟说了算」取决于这次
// 调用是谁发的：快 30s 的副本把未过期票据判成过期（且先删后判——这次误判
// 同时删掉了票，真正持有者随后消费失败且不可恢复）；慢的副本让过期票据
// 仍可重放。修复后时间权威在 Backend：Put 按存储时钟落 expires_at，
// Take/GC 用存储时钟比较——接口层面没有任何接收节点时钟的入口。
//
// 判据的构造：存储时钟刻意落在节点真实时钟的 25 年前（2001 vs 2026）。
// 任何一处偷用节点时钟（time.Now）都会把「未过期」翻成「过期」，结论
// 立刻可辨——不是靠「看起来对」。

package ticket

import (
	"sync"
	"testing"
	"time"
)

// storageClock 测试用存储时钟（可推进；扮演 DB 的 clock_timestamp /
// Redis Lua 的 TIME）。它就是本用例里的**唯一时间真相**。
type storageClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *storageClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *storageClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

// Test过期判定只随存储时钟 两个节点共享一个存储：A 签发、B 消费；过期
// 结论只随存储时钟推进。节点的本地时钟（真实时间是 2026 年，存储时钟是
// 2001 年）不参与任何判定——新接口也没有入口能把它传进去。
func Test过期判定只随存储时钟(t *testing.T) {
	sc := &storageClock{at: time.Unix(978307200, 0)} // 2001-01-01T00:00:00Z
	backend := NewMemoryBackendWithClock(0, sc.Now)

	// 两个「节点」：同一跨进程存储的两份 Store 句柄。
	nodeA := NewWithBackend(backend)
	nodeB := NewWithBackend(backend)

	id, exp, err := nodeA.Issue(Binding{Subject: "s1"}, time.Minute)
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	// Put 按**存储时间**落 expires_at，Issue 返回的必须是库里同一个时刻。
	wantExp := sc.Now().Add(time.Minute)
	if !exp.Equal(wantExp) {
		t.Fatalf("Issue 返回的过期时刻必须由存储时钟算（要 %v 实得 %v——含节点时钟成分）", wantExp, exp)
	}
	mb, ok := backend.(*memoryBackend)
	if !ok {
		t.Fatalf("构造函数应返回内存参考实现，实得 %T", backend)
	}
	mb.mu.Lock()
	storedExp := mb.m[id].expiresAt
	mb.mu.Unlock()
	if !storedExp.Equal(wantExp) {
		t.Fatalf("库里的 expires_at 必须由存储时钟落（要 %v 实得 %v）", wantExp, storedExp)
	}

	// 存储时钟只推进 30s：另一节点消费必须成功。
	// （节点真实时钟此刻距过期时刻已 25 年——偷用节点时钟必红。）
	sc.Advance(30 * time.Second)
	if _, ok := nodeB.Consume(id); !ok {
		t.Fatal("存储时钟未过期时另一节点必须能消费（节点时钟不得参与判定）")
	}

	// 反面对照：存储时钟推过 TTL 后，换一个节点消费必须失败——
	// 慢时钟不得让过期票据继续放行。
	id2, _, err := nodeB.Issue(Binding{Subject: "s2"}, time.Minute)
	if err != nil {
		t.Fatalf("第二次签发失败: %v", err)
	}
	sc.Advance(61 * time.Second) // 距 id2 签发已过 61s
	if _, ok := nodeA.Consume(id2); ok {
		t.Fatal("存储时钟已过期的票据必须消费失败（慢时钟不得放行重放）")
	}

	// GC 同一把尺：按存储时钟收过期票。
	id3, _, err := nodeA.Issue(Binding{Subject: "s3"}, time.Minute)
	if err != nil {
		t.Fatalf("第三次签发失败: %v", err)
	}
	sc.Advance(2 * time.Minute)
	if n := nodeB.GC(); n != 1 {
		t.Fatalf("GC 应按存储时钟清掉 1 张过期票，实得 %d", n)
	}
	if _, ok := nodeA.Consume(id3); ok {
		t.Fatal("被 GC 的票据不得再消费")
	}
}

// Test内存后端注入时钟即存储时钟 钉住缺省构造的接缝：NewWithClock 注入的
// 时钟只落到进程内参考后端（存储侧），不是 Store 的节点时钟。
func Test内存后端注入时钟即存储时钟(t *testing.T) {
	at := time.Unix(978307200, 0)
	sc := &storageClock{at: at}
	s := NewWithClock(0, sc.Now)

	id, exp, err := s.Issue(Binding{Subject: "s"}, time.Minute)
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	if !exp.Equal(at.Add(time.Minute)) {
		t.Fatalf("过期时刻必须由注入的存储时钟算（要 %v 实得 %v）", at.Add(time.Minute), exp)
	}
	// 推进注入的存储时钟 ⇒ 判定随之改变（这就是「用注入时钟实现同一语义」）。
	sc.Advance(2 * time.Minute)
	if _, ok := s.Consume(id); ok {
		t.Fatal("存储时钟推过 TTL 后必须消费失败")
	}
}
