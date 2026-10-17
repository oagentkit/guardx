# AGENTS.md — oagentkit/guardx

> 安全围栏，6 个包：`fence` `logredact` `egress` `permgate` `bashguard` `audit`
> module：`github.com/oagentkit/guardx` · org：[oagentkit = Open Agent Kit](https://github.com/oagentkit)
> 矩阵分层：**tier 0（基础层）**

## 本仓包含

```
audit/  bashguard/  egress/  fence/  logredact/  permgate/
```

## 硬规则

### 分层与依赖

- 依赖严格自底向上，**禁止反向依赖**。本仓是 tier 0，任何矩阵内模块都不得被本仓依赖。
- 外部依赖仅 `github.com/oekit/logx`（audit 用）与 `mvdan.cc/sh/v3`（bashguard 解析 shell AST）。
- **新增外部依赖前先确认 `oekit/pkg` 里没有。**

### 安全语义不可弱化（本仓的全部价值所在）

- **`fence`** —— 任何把 LLM 产出或用户输入拼进 prompt 的路径都必须过 `EscapeUntrusted`。
  不得为了「可读性」绕过它。
- **`egress`** —— 任何由 LLM 决定的 URL 出站前必须过 egress 判定。
  **不得新增「信任 LLM 给出的 URL」这类豁免分支** —— 那是提示词注入的直接落点。
- **`bashguard`** —— 静态解析，不执行命令。**不得改成 exec 执行后再判断**。
- **`permgate`** —— 许可判定的默认值必须是**拒绝**，白名单显式开。
  新增能力时默认拒绝，不要用「未配置即放行」。

### 错误处理

- 一律使用 `github.com/oekit/pkg/errors`；业务错误用 BizError。
- 所有 error 禁止 `_` 忽略。**安全相关路径尤其禁止吞 error** —— 判定失败必须阻断而非放行。

### 日志

- 本仓是矩阵里**唯一允许直接依赖 `oekit/logx` 的 tier0 仓**（审计需要）。
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
| 并发/流控/熔断/事件总线 | `github.com/oagentkit/runtime` |
| 工具优先级与并发调度 | `github.com/oagentkit/toolgate` |
| 通用 errors/stringx/encoding/mathx | `github.com/oekit/pkg` |
