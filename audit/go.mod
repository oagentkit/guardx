module github.com/oagentkit/guardx/audit

go 1.26.0

toolchain go1.27.2

require (
	github.com/oagentkit/guardx v0.6.0
	github.com/oekit/logx v0.7.1
)

// 本地开发：audit 与父模块在同一仓、同一提交上开发，用 replace 指向父模块，
// 免得每改一次父模块都要先发 tag 才能验证。
//
// ⚠️ replace **只在主模块生效**：消费方 import github.com/oagentkit/guardx/audit 时
// 这段被忽略，走 require 里的正式版本（父模块 v0.6.0 起已不含 audit 包）。
replace github.com/oagentkit/guardx => ../
