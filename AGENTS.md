# AGENTS.md — oagentkit/guardx

> 安全围栏，7 个包：`fence` `injectband` `logredact` `egress` `permgate` `bashguard` `audit`
> module：`github.com/oagentkit/guardx` · org：[oagentkit = Open Agent Kit](https://github.com/oagentkit)
> 矩阵分层：**tier 0（基础层）**

## 本仓包含

```
fence/  injectband/  logredact/  egress/  permgate/      ← 主模块，零外部依赖
audit/     （嵌套模块 github.com/oagentkit/guardx/audit）
bashguard/ （嵌套模块 github.com/oagentkit/guardx/bashguard）
```

**本仓含 3 个 Go module**（主模块 + 2 个嵌套子模块），但只有 1 个 import 路径前缀
（`github.com/oagentkit/guardx/...`）——**import 路径没变**，下游不用改代码。

### 为什么拆成嵌套模块（依赖地板）

主模块**必须零外部依赖**。原因：`import "github.com/oagentkit/guardx/logredact"`
会把**整个模块的 require 拉进消费方的模块图**。本仓曾把 `oekit/logx`（audit 用）
与 `mvdan.cc/sh/v3`（bashguard 解析 shell AST）放在主模块里，于是**只想脱敏的下游
也得吃下这两条第三方依赖**——下游的「核心零依赖」纪律（不引 SDK/框架/驱动，
降级路径不能被破坏）只能靠豁免名单放行，那是把纪律开成了例外。

拆开之后：

| module | 包 | 外部依赖 | 谁在用 |
|---|---|---|---|
| `github.com/oagentkit/guardx` | fence / injectband / logredact / egress / permgate | **无** | 绝大多数下游 |
| `github.com/oagentkit/guardx/audit` | audit | `oekit/logx` | 需要审计留痕的编排层 |
| `github.com/oagentkit/guardx/bashguard` | bashguard | `mvdan.cc/sh/v3` | 需要 shell 静态裁决的编排层 |

`go list -m all` 在主模块下只有一行 —— 这条就是门禁要守的东西。

**新包默认进主模块**（零依赖）。要引第三方库的包，自己开嵌套子模块
（`audit/` `bashguard/` 是样板：子目录放自己的 `go.mod`，module path = 父路径 + 包名）。

## 硬规则

### 分层与依赖

- 依赖严格自底向上，**禁止反向依赖**。本仓是 tier 0，任何矩阵内模块都不得被本仓依赖。
- **主模块不得有外部依赖**（`require` 段必须为空）。需要第三方库 → 开嵌套子模块。
- 外部依赖仅允许出现在嵌套子模块里：`github.com/oekit/logx`（audit 用）、
  `mvdan.cc/sh/v3`（bashguard 解析 shell AST）。
- **新增外部依赖前先确认 `oekit/pkg` 里没有。**

### 安全语义不可弱化（本仓的全部价值所在）

- **`fence`** —— 任何把 LLM 产出或用户输入拼进 prompt 的路径都必须过 `EscapeUntrusted`。
  不得为了「可读性」绕过它。
- **`injectband`** —— 与 `fence` 互补，封的是**相反方向**：`fence` 标「这是不可信数据」
  （数据侧），`injectband` 标「这是系统带外注入」（系统侧）。系统写入模型的提示必须过
  `Wrap` / `SanitizeBody`，**不得为省事直接拼字符串** —— 那正是伪造身份抬升权限的入口。
  两者不可互相替代：只做 `fence` 时，攻击者不必逃出数据区，写一个像系统注入的标签即可。
- **`egress`** —— 任何由 LLM 决定的 URL 出站前必须过 egress 判定。
  **不得新增「信任 LLM 给出的 URL」这类豁免分支** —— 那是提示词注入的直接落点。
- **`bashguard`** —— 静态解析，不执行命令。**不得改成 exec 执行后再判断**。
- **`permgate`** —— 许可判定的默认值必须是**拒绝**，白名单显式开。
  新增能力时默认拒绝，不要用「未配置即放行」。

### 错误处理

- 一律使用 `github.com/oekit/pkg/errors`；业务错误用 BizError。
- 所有 error 禁止 `_` 忽略。**安全相关路径尤其禁止吞 error** —— 判定失败必须阻断而非放行。

### 日志

- `oekit/logx` 只允许出现在 `audit` **嵌套子模块**里（审计需要）；主模块不引。
- 日志必须经 `logredact` 打码后再落，**不得直接打印原始载荷**。
- 审计走 `audit.New(log, service)`；`log` 为 nil 时回退 `logx.NewAuditLogger`
  （级别锁 `Info`，不受 `LOG_LEVEL` 降级 —— 这是刻意的，别改回普通 logger）。

### 并发安全

- 禁止裸 `go func`：用 `github.com/oekit/concurrency/async` 的 GoSafe 系列。
- 许可判定链若持有状态，必须有 `-race` 回归测试兜底。

### API 设计

- 函数选项模式命名 `XxxOption`（禁止裸 `Option`，多包 co-import 会冲突）。
- 导出符号 PascalCase + godoc 注释；包文档放 `doc.go`。

## 明确不属于本仓的

| 能力 | 归属 |
|---|---|
| 子进程最小环境 / 执行封装 | `github.com/oagentkit/runtime/procx` |
| 并发/流控/事件总线 | `github.com/oagentkit/runtime` |
| 熔断 | `github.com/oekit/concurrency/breaker`（`runtime/breaker` 已于 runtime v0.3.0 退役） |
| 工具优先级与并发调度 | `github.com/oagentkit/toolgate` |
| 通用 errors/stringx/encoding/mathx | `github.com/oekit/pkg` |
