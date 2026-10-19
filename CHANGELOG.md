# guardx CHANGELOG

> 本文件由 `matrix-tools/scripts/gen_changelogs.py` 从 git 历史生成，按 tag 切段、取每段内的 conventional commit 渲染。

## [v0.5.0] — 2026-10-19

- 杂务(deps)：依赖地板对齐远端最新（logx v0.7.1） (#13)

## [v0.4.1] — 2026-10-19

### 修复(egress)：补 0.0.0.0/8 拦截，堵 this network 段 SSRF 缺口 (#2)

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

### 修复(agents)：把熔断从 runtime 归属里拆出来，指向 oekit/concurrency/breaker (#1)

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

- CI：接入 org 共享门禁（规则本体在 oagentkit/.github）

- 文档(agents)：补 injectband 到包清单与安全语义硬规则
- 文档：修正 README/AGENTS.md —— 原为 agent-harness 的整份复制残留
