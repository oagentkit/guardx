package wire

import (
	"log"
	"runtime/debug"
)

// goSafe 包内安全 goroutine：panic 被 recover 并落日志，不让一次协议处理的
// panic 打死整个进程（仓规「禁裸 go func」）。
//
// 为什么不直接用 oekit/concurrency/async.GoSafe：本仓 go.mod 只依赖
// github.com/oekit/pkg（AGENTS.md「零第三方依赖」——依赖面变更走专门评审，
// 不随功能修复合入），引 oekit/concurrency 会多一条 require。故按 oekit/pkg
// 自己的先例（其 CHANGELOG：「async.GoSafe→包内 goSafe」）在包内落一个同型
// 函数：意图一致（panic 不外泄、有观测面），依赖面不动。
//
// 日志用标准库 log（标准库不是第三方依赖）。panic 载荷是宿主 handler 抛出的
// 异常值，不是工具原始输出，不在 logredact 管辖的「载荷日志」路径上。
func goSafe(fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[wire] goroutine panic recovered: %v\n%s", r, debug.Stack())
			}
		}()
		fn()
	}()
}
