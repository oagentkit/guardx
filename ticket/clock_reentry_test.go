package ticket

// 宿主注入的时钟回调不得在持锁期间调用（issue #317）。
//
// ticket.NewMemoryBackendWithClock 的时钟是**公开装配接缝**，由宿主注入。
// 宿主在回调里顺手读一次本包（票据数 / 当前时刻）是极自然的写法；若实现
// 在 b.mu 之内调 now()，sync.Mutex 不可重入 ⇒ 进程永久死锁（不是错误返回，
// 没有超时兜底）。这组用例带超时保护：超时即判红。

import (
	"sync/atomic"
	"testing"
	"time"
)

func mustNotDeadlock(t *testing.T, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("%s 在持锁期间调用了宿主时钟回调：回调重入本包即死锁（3s 未返回）", what)
	}
}

// TestPutClockCallbackReentry Putt 的时钟回调重入 Len 必须正常返回。
func TestPutClockCallbackReentry(t *testing.T) {
	var b Backend
	b = NewMemoryBackendWithClock(8, func() time.Time {
		_, _ = b.Len() // 宿主回调重入本包
		return time.Unix(1700000000, 0)
	})
	mustNotDeadlock(t, "Put", func() {
		exp, err := b.Put("id-1", Binding{Subject: "s"}, time.Minute)
		if err != nil {
			t.Errorf("Put: %v", err)
			return
		}
		if want := time.Unix(1700000000, 0).Add(time.Minute); !exp.Equal(want) {
			t.Errorf("expiresAt = %v, want %v", exp, want)
		}
	})
}

// TestTakeClockCallbackReentry Take 的时钟回调重入 Len 必须正常返回。
func TestTakeClockCallbackReentry(t *testing.T) {
	var reenter atomic.Bool
	var b Backend
	b = NewMemoryBackendWithClock(8, func() time.Time {
		if reenter.Load() {
			_, _ = b.Len()
		}
		return time.Unix(1700000000, 0)
	})
	if _, err := b.Put("id-1", Binding{Subject: "s"}, time.Minute); err != nil {
		t.Fatalf("播种失败: %v", err)
	}
	reenter.Store(true)
	mustNotDeadlock(t, "Take", func() {
		binding, ok, err := b.Take("id-1")
		if err != nil || !ok || binding.Subject != "s" {
			t.Errorf("Take = (%+v, %v, %v)", binding, ok, err)
		}
	})
}

// TestGCClockCallbackReentry GC 的时钟回调重入 Len 必须正常返回。
func TestGCClockCallbackReentry(t *testing.T) {
	var reenter atomic.Bool
	var b Backend
	b = NewMemoryBackendWithClock(8, func() time.Time {
		if reenter.Load() {
			_, _ = b.Len()
		}
		return time.Unix(1700000000, 0)
	})
	if _, err := b.Put("id-1", Binding{Subject: "s"}, time.Minute); err != nil {
		t.Fatalf("播种失败: %v", err)
	}
	reenter.Store(true)
	mustNotDeadlock(t, "GC", func() {
		if _, err := b.GC(); err != nil {
			t.Errorf("GC: %v", err)
		}
	})
}
