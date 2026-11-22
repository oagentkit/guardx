package wire

import "github.com/oekit/concurrency/async"

// goSafe 包内安全 goroutine 入口：单源委托 oekit/concurrency/async.GoSafe
// （panic 收编 + 全局 PanicHandler 面）。
//
// 此前是包内私有实现：recover 后用标准库 log 落盘——panic 不外泄但宿主的
// PanicHandler 收编不到 wire 的 panic，两套 panic 观测面并存（跨 org 协议
// 审计确认的分裂点）。改走 async 单源后，wire 的 panic 进入矩阵统一的
// PanicHandler 面（未设置时 async 自带 stderr 兜底，等价旧形态）。
//
// 依赖面说明：wire 的「零第三方依赖」口径是**基座白名单内零三方**（oekit/pkg
// + oekit/concurrency 都是第一方 tier0，见 guardx go.mod 与 AGENTS.md 修订），
// 不是「零 require」。依赖面变更按仓规走专门评审——本 PR 即该评审的载体。
func goSafe(fn func()) {
	async.GoSafe(fn)
}
