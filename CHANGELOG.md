# guardx CHANGELOG

> 本文件由 `matrix-tools/scripts/gen_changelogs.py` 从 git 历史生成，按 tag 切段、取每段内的 conventional commit 渲染。

## [v0.8.2] — 2026-10-20

### 修复(go)：tier0 基础包地板降到 go 1.24.0，CI go-version 同步到 1.24

本仓是 tier0 基础包（零重量级第三方地板，可被零依赖核心安全依赖），
但 go 指令声明的是 1.26.0——地板被无谓抬高，把 Go 1.24 的用户挡在门外。
## 依据
**依赖链全是 1.24 的包**：本仓唯一依赖 `github.com/oekit/pkg v0.16.0`（go 1.24.0），
依赖链上没有任何要求更高版本的包。
**代码本身兼容 1.24**：用真实 go1.24.0 工具链（`GOTOOLCHAIN=go1.24.0`）
build + test 全绿——不是推断，是实跑。
**门槛是 go 指令，不是 toolchain**（编译器实证）：
- `go 1.28.0` → 被拒：`go.mod requires go >= 1.28.0 (running go 1.27.1; GOTOOLCHAIN=local)`
- `go 1.24.0` + `toolchain go1.28.0` → 通过
## toolchain 行的取舍：删掉
toolchain **不构成门槛**（上面已实证），但 `toolchain go1.27.2` 会让 `go` 命令
**自动下载** 1.27.2，与「最低支持版本是 1.24」的精神相悖——用户以为自己用
1.24 在编译，工具链却被悄悄换成了 1.27.2。故删除该行。
这也与基座 org 的做法一致：oekit 的 pkg / concurrency / core / logx / metrics /
kitx 六个基础仓一律是 `go 1.24.0` + **无 toolchain 行**。
## 改动
- `go.mod`：`go 1.26.0` → `go 1.24.0`；删 `toolchain go1.27.2`
- `.github/workflows/ci.yml`：`go-version: '1.26'` → `'1.24'`
CI 的 go-version 与 go.mod 的 go 指令**成对**——这是跨层通用纪律，不因本次
降级而放松。CI 用高版本构建、go.mod 承诺低版本时，CI 全绿但用户按最低版本
编译失败，门禁绿了而承诺没兑现。
## 未受影响
- `require` 段（依赖地板钉）**未动**，`go mod tidy -diff` 零差异、go.sum 未变
- 内部 require 版本不变 ⇒ 不影响任何下游的 MVS
- 对外产物（versions.json / llms.txt）不记录 go 版本，无需刷新
## 验证
- `GOTOOLCHAIN=go1.24.0 go build ./...` → exit 0
- `GOTOOLCHAIN=go1.24.0 go test ./...` → 全绿
- `go mod tidy -diff` → 零差异
门禁见 oagentkit/matrix-tools PR：`scripts/verify_go_floor.py`
（tier0 必须 1.24.x + CI go-version 与 go.mod 成对，判据独立不复用生成器）。

## [v0.8.1] — 2026-10-20

### 修复(docs)：egress 不校验 scheme——改为实际行为并写明误用边界

Co-authored-by: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

## [v0.8.0] — 2026-10-19

### 新增(invoke)：接收 toolgate/invoke —— 框架无关的调用链原语落到零依赖底座

自 github.com/oagentkit/toolgate/invoke 迁入（toolgate v0.11.0 起该路径退役）。
为什么迁：invoke 的包文档自己写着「刻意不携带任何框架类型（如 policy.Op）：
本包与 policy/toolegate 无耦合」——它是**框架无关的原语**，却被放在带 eino
家族的重仓里。实测：import 这个包会让消费方的模块图多出 34 个第三方模块
（eino + sonic + mcp-go 全家），而它自身的 import 面只有 oekit/pkg/errors。
迁到本仓后，import 它只多出 oekit/pkg（第一方基座，零第三方依赖）。
与 permgate 同族（许可判定链 / 不可绕过的调用链，都是「工具调用过程的强制」）。
本仓仍零第三方依赖：go list -m all 只有自己 + oekit/pkg。

## [v0.7.0] — 2026-10-19

### 重构：audit / bashguard 迁出本仓，回到单 module 零依赖

BREAKING CHANGE: github.com/oagentkit/guardx/audit 与
github.com/oagentkit/guardx/bashguard 不再属于本仓模块。
迁往：
- audit     → github.com/oagentkit/obs/audit      （依赖 oekit/logx）
- bashguard → github.com/oagentkit/tools/bashguard（依赖 mvdan.cc/sh/v3）
为什么：Go 的依赖面按 **module** 结算，不按 package。只 import logredact 的下游，
模块图里也会多出本仓的整条 require（实测拆分前会多出 oekit/logx 与 mvdan.cc/sh）。
本仓是 tier 0 基础层，地板被所有下游继承——带重依赖的能力该待在本来就带该
依赖的重仓里（obs 本就带 logx，tools 是重仓）。
本仓回到：**1 个 Go module、1 条版本线、零外部依赖**（go list -m all 只有自己
一行）。此前短暂的嵌套 module 布局（audit/ 与 bashguard/ 各带 go.mod）作废：
那会让「一仓一 module」的矩阵模型破掉——版本线分裂、矩阵与门禁都得加特例。
⚠️ 嵌套 module 的两个 tag（audit/v0.1.0 / bashguard/v0.1.0）**保留不动**
（已发布物不动，动了会毁掉消费方 go.sum 里的校验和），但那条线**已冻结**，
不再有后续版本——新代码请用上面的新路径。
关联 oagentkit/guardx#3

- 测试(logredact)：修 ineffassign（append 结果未使用）

## [v0.6.0] — 2026-10-19

### 新增(logredact)!：规则表可组合 + 保定位线索掩码档；audit/bashguard 拆嵌套模块

修 #3。
一、规则表公开且可组合
- Rule 公开（Name/Re/Repl/Style/Keep/Group），Rules() 给内置表副本
- RedactWith(s, extra) / NewRedactor(extra)：下游可追加自己的凭据形态
- 应用顺序明确：**先内置、后扩展**（内置更精确，先跑它扩展才拿不到原始凭据）
- 扩展表里 Re=nil 的规则跳过而不是 panic
二、补「保定位线索的不可逆掩码」档
- MaskHint / MaskHintWith：保留首尾各 Keep 字符，中间恒为固定长度星号
- 保留位**封顶**、输出长度**固定** → 不随原值长度泄露信息
- 长度不足 keep*4 时全量打码（留 8 藏 1 等于没藏）
- Rule.Style=MaskStyleHint + Group 圈出凭据本体，保留额度才花在凭据上
- 与全量打码是**不同档**：前者认不出是哪一条，后者认得出但还原不了
三、依赖面收干净（主模块零外部依赖）
- audit → 嵌套模块 github.com/oagentkit/guardx/audit（依赖 oekit/logx）
- bashguard → 嵌套模块 github.com/oagentkit/guardx/bashguard（依赖 mvdan.cc/sh）
- import 路径**不变**（github.com/oagentkit/guardx/audit 等），下游代码不用改
- 主模块 go list -m all 只剩自己一行：import logredact 不再把 logx / sh 拖进
  下游的模块图（下游的「核心零依赖」纪律不必再靠豁免名单放行）

## [v0.5.0] — 2026-10-19

- 杂务(deps)：依赖地板对齐远端最新（logx v0.7.1）

matrix-tools 的 verify_dep_floors.py 首次全矩阵扫描查出：43 条第一方依赖里
28 条落后，横跨 11 个仓；本仓是其中之一。
所升版本与本仓原钉版本相比源码零改动，逐版实测确认：
- textx v0.3.0→v0.4.0 / obs v0.4.1→v0.5.0 / runtime v0.5.0→v0.6.0 /
  mcpkit v0.5.1→v0.6.0  全树逐字节相同（diff -rq 退出码 0）
- oekit/pkg v0.14.0→v0.15.1  仅新增 urlguard 包（纯标准库，pkg 的 go.mod
  连 require 块都没有，零新增三方依赖）
- oekit/concurrency v0.17.0→v0.17.1  仅三个文档文件
- oekit/logx v0.7.0→v0.7.1  仅 CI 配置与文档
无 API 变更、无兼容风险。
本地门禁：go mod tidy -diff 无输出 / go build / go vet / gofmt / go test -race 全通过。


## [v0.4.1] — 2026-10-19

### 修复(egress)：补 0.0.0.0/8 拦截，堵 this network 段 SSRF 缺口

netip 的 IsUnspecified() 只匹配全零这一个地址，不是 0.0.0.0/8 的判定，
而该段此前不在 ipv4ExplicitBlocks 里——0.1.2.3 / 0.255.255.255 一类
"this network"（RFC 1122）目标在纯 IP 判定层全放行，是一条可用的 SSRF
路径。把 0.0.0.0/8 补进显式段表即同时闭合三种载体形态：
  0.1.2.3 / 0.255.255.255        裸字面量
  ::ffff:0.1.2.3                 IPv4-mapped（Unmap 后同套 v4 策略）
  64:ff9b::0.1.2.3               NAT64 well-known prefix（还原后同上）
0.0.0.0 字面量仍走 IsUnspecified 分支，AllowLoopback 的放行语义不变；
/8 余下整段与 CGNAT/benchmark 同列，不在 Options 放行面内。
测试钉住边界：0.0.0.0 / 0.1.2.3 / 0.255.255.255 三例加 mapped、NAT64
两个逃逸形态；1.0.0.0 作为紧邻上界的正例，防「补段」补成 /7。

## [v0.4.0] — 2026-10-18

- 与 v0.3.0 相比无代码差异（版本号/打包变更）

## [v0.3.0] — 2026-10-18

### 新增(injectband)：系统带外注入的防伪包裹通道（第 7 包）

自 agent-harness/reminder 下沉。提示注入卫生的两个方向互补，此前本仓只有 fence 封数据侧：
  fence      不可信内容圈进数据区，防其伪造边界标记越权取指令待遇
  injectband 系统带外注入打来源标记，并转义 body 内伪造的同形标签
只做 fence 时，系统提示与用户文本在模型眼里仍是同一等公民——攻击者不必逃出数据区，只需写一个像系统注入的标签即可抬升身份。injectband 补这个缺口。
包名不用 reminder：那是载体名，在 Go 生态会被读成「定时提醒」，与本仓全机制名的风格（fence/egress/permgate）不符，点名机制才自解释。
测试夹具已去领域词（原「负载高」等运维词面不该出现在 tier 0 原语仓）。覆盖率 100%。

### 新增：guardx 仓建立——安全围栏（6 包）

从 agentkit 单仓切出 tier0 基础层模块，module 路径 github.com/oagentkit/guardx。
收编 6 个包：
- fence     中和不可信文本中的 markdown 结构，防提示词注入
- logredact 日志/审计载荷凭据脱敏
- egress    LLM 可控 URL 的字面量层 SSRF 防护
- permgate  工具调用许可判定链
- bashguard bash 命令静态风险解析（真 shell AST，不执行）
- audit     审计日志（经 logx.NewAuditLogger，级别锁 Info 不受 LOG_LEVEL 降级）
外部依赖：github.com/oekit/logx（audit）、mvdan.cc/sh/v3（bashguard），无矩阵内依赖。
AGENTS.md 立了「安全语义不可弱化」一节：egress 不得加 LLM URL 豁免、
permgate 默认拒绝、bashguard 不得改成 exec 后判。
门禁：go build / go vet / go test -race 6 包全绿，gofmt 干净。

### 修复(agents)：把熔断从 runtime 归属里拆出来，指向 oekit/concurrency/breaker

`AGENTS.md` 的归属表写的是：
    | 并发/流控/熔断/事件总线 | `github.com/oagentkit/runtime` |
这条比 textx 那条更阴险：**语法完全合法，且指向的仓真实存在**，
只是其中已经没有 `breaker` 包了（runtime v0.3.0 移除）。
人工扫读时看不出任何异常，只有机器比对包清单才发现得了。
拆成两行：
    | 并发/流控/事件总线 | `github.com/oagentkit/runtime` |
    | 熔断 | `github.com/oekit/concurrency/breaker`（`runtime/breaker` 已于 runtime v0.3.0 退役） |
配套门禁：matrix-tools 的 `scan_stale_refs.py` 已接入 org CI。

- 杂务(deps)：oekit 三模块升至最新（pkg v0.13.0 / concurrency v0.12.0 / logx v0.7.0）

拿到上游新增能力：
- concurrency #22 RetryableWithHeaders：403 头感知判定（次级限流 / 主限流耗尽）
- concurrency #23 FanInLimit：受限并发扇出
- concurrency #24 WithTokenClock、#21 Lockout（keyed lockout/penalty）
- logx #12 TraceHandler：给裸 slog.Handler 注入 trace_id
破坏性变更核对（均无影响）：
- logx v0.7.0 ParseLogLevel 签名改为 (Level, error) —— 我们未使用该函数
- concurrency v0.9.0 的 Slot.Panicked 废弃 —— rag 已迁到 Slot.Err + errors.As
门禁：go build / go vet / go test -race 全绿。


- CI：接入 org 共享门禁（规则本体在 oagentkit/.github）

- 文档(agents)：补 injectband 到包清单与安全语义硬规则

7b2a90b 加包时改的 AGENTS.md 被后续重写（f5cb3a9 的归属表版）覆盖，本 commit 在新版基础上补漏，不回退重写。
三处：标题包数 6→7、本仓包含目录补 injectband/、安全语义硬规则补 injectband 条。
硬规则强调 fence 与 injectband 封相反方向且不可互替——只做 fence 时攻击者不必逃出数据区，写一个像系统注入的标签即可抬升身份。删除任一个都会开真实的注入面。

- 文档：修正 README/AGENTS.md —— 原为 agent-harness 的整份复制残留

建仓时从 agent-harness 复制了文档没改，导致：README 标题写着「agent-harness · 多智能体编排通用内核」、包清单列的是 agent-harness 的 20 个包（本仓实际 7 个）、AGENTS.md 通篇引用本仓不存在的 make check 与 harness-* 门禁规则。
后果不只是文档不准：AGENTS.md 是 AI 代理的工作纪律来源，它让后续在本仓干活的代理按一套不存在的门禁和错误的边界（宿主仓禁令、运维词表）做判断。
重写为 guardx 自己的内容：包清单、提示注入两个方向的互补关系、egress 不解析 DNS 的误用陷阱、机制与策略内容的分界（这是 tier 0 特有纪律，agent-harness 那套「资产归宿主」不适用）。
