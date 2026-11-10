package wire

// 2026-11-11 issue 清零战回归测试（#143）：钉住 Budget 惰建并发安全。

import (
	"sync"
	"testing"
)

// TestBudgetConcurrentFirstChargeSingleState_Issue143 并发首笔记账必须落在
// 同一个 state 上——原无锁 check-then-act 让两个 goroutine 各建一个
// budgetState（-race 必红），MaxCalls=N 实放约 2N，父侧预算权威被击穿。
func TestBudgetConcurrentFirstChargeSingleState_Issue143(t *testing.T) {
	const maxCalls = 100
	b := Budget{MaxCalls: maxCalls} // 零值惰建路径（NewServer/WithBudget 之外的形态）
	var wg sync.WaitGroup
	granted := make(chan struct{}, maxCalls*2)
	for i := 0; i < maxCalls; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if b.charge(1, 0) {
				granted <- struct{}{}
			}
		}()
	}
	wg.Wait()
	close(granted)
	if n := len(granted); n != maxCalls {
		t.Fatalf("MaxCalls=%d 应恰好放行 %d 笔，实放 %d（记账分裂则多放）", maxCalls, maxCalls, n)
	}
	usedCalls, _ := b.Used()
	if usedCalls != maxCalls {
		t.Fatalf("Used 应为 %d，实得 %d", maxCalls, usedCalls)
	}
}
