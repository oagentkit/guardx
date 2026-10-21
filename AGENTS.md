# AGENTS.md — oagentkit/guardx

> 安全围栏，9 个包：`fence` `injectband` `logredact` `egress` `permgate` `invoke` `toolfail` `sandbox` `wire`
> module：`github.com/oagentkit/guardx` · org：[oagentkit = Open Agent Kit](https://github.com/oagentkit)
> 矩阵分层：**tier 0（基础层）**

## 本仓包含

```
fence/  injectband/  logredact/  egress/  permgate/  invoke/  toolfail/  sandbox/  sandbox/wire/
```

**本仓是 1 个 Go module、1 条版本线、零外部依赖。**

### 依赖地板：为什么主模块必须零外部依赖

`import "github.com/oagentkit/guardx/logredact"` 会把**整个模块的 require 拉进消费方的
模块图**（Go 按 module 结算依赖面，不按 package）。实测：拆分前只 import logredact 的
消费方，模块图里会多出 `oekit/logx` 与 `mvdan.cc/sh/v3`。

所以本仓的两个带重依赖的包**已迁出**（2026-10-19，guardx v0.7.0）：

| 原位置 | 现位置 | 迁出理由 |
|---|---|---|
| `guardx/audit` | [`github.com/oagentkit/obs/audit`](https://github.com/oagentkit/obs) | 依赖 `oekit/logx`（审计日志门面）；obs 本就带 logx |
| `guardx/bashguard` | [`github.com/oagentkit/tools/bashguard`](https://github.com/oagentkit/tools) | 依赖 `mvdan.cc/sh/v3`（真 shell AST 解析）；tools 是重仓 |

迁出后主模块 `go list -m all` 只有自己一行 —— **这条就是门禁要守的东西**。

> ⚠️ `github.com/oagentkit/guardx/audit` 与 `.../guardx/bashguard` 这两条 import 路径
> 已**退役**（它们曾短暂以嵌套 module 形式存在，tag `audit/v0.1.0` / `bashguard/v0.1.0`
> 仍在，但那条线**已冻结**，不再有后续版本）。新代码请用上面表里的新路径。

**新包默认进本仓**（零依赖）。要引第三方库的包 → 它不属于 tier 0，**另起一个仓**
（`obs` / `tools` 是样板：重依赖能力放在本来就带该依赖的重仓里）。

## 硬规则

### 分层与依赖

- 依赖严格自底向上，**禁止反向依赖**。本仓是 tier 0，任何矩阵内模块都不得被本仓依赖。
- **本仓不得有外部依赖**（`require` 段必须为空）。需要第三方库 → 另起仓，不要在本仓开嵌套子模块
  （嵌套子模块会让「一仓一 module」的矩阵模型破掉：版本线分裂、矩阵与门禁都得加特例）。
- **新增外部依赖前先确认 `oekit/pkg` 里没有。**
- 本仓是 tier 0 **基础层**：地板被所有下游继承，任何一条第三方依赖都会顺着
  依赖树扩散到矩阵每一层。带重依赖的能力属于重仓（obs / tools / llm …）。

### 安全语义不可弱化（本仓的全部价值所在）

- **`fence`** —— 任何把 LLM 产出或用户输入拼进 prompt 的路径都必须过 `EscapeUntrusted`。
  不得为了「可读性」绕过它。
- **`injectband`** —— 与 `fence` 互补，封的是**相反方向**：`fence` 标「这是不可信数据」
  （数据侧），`injectband` 标「这是系统带外注入」（系统侧）。系统写入模型的提示必须过
  `Wrap` / `SanitizeBody`，**不得为省事直接拼字符串** —— 那正是伪造身份抬升权限的入口。
  两者不可互相替代：只做 `fence` 时，攻击者不必逃出数据区，写一个像系统注入的标签即可。
- **`egress`** —— 任何由 LLM 决定的 URL 出站前必须过 egress 判定。
  **不得新增「信任 LLM 给出的 URL」这类豁免分支** —— 那是提示词注入的直接落点。
- **`bashguard`（已迁至 `github.com/oagentkit/tools/bashguard`）** —— 静态解析，
  不执行命令。**不得改成 exec 执行后再判断**。
- **`permgate`** —— 许可判定的默认值必须是**拒绝**，白名单显式开。
  新增能力时默认拒绝，不要用「未配置即放行」。
- **`invoke`** —— 工具调用的**统一契约与不可绕过的调用链**：链的构造即保证
  （构造器不给出绕过路径）。它刻意**不携带任何框架类型**（不绑 eino / policy 的
  类型），审计语义由各 Stage 自己从 Name/Server/Args 读——所以它是**框架无关的原语**，
  放本仓而不是工具治理仓。
- **`toolfail`** —— 工具失败的**分类与处置契约**。三条硬规则：
  - **不可分类 = 不可重试**（保守缺省）：判据缺失时两种误判成本不对称——
    误判可重试是把一次失败放大成 N 次，还可能重复施加副作用。
  - **重发安全与重试价值是两个正交维度**：超时值得重试，但服务端可能已执行，
    原样重发即重复施加副作用。只看「可重试」的调用方必然在这两种误判里选一个。
  - **策略是数据不是 if 链**：类别 → 处置的映射写进单源策略表，改表必然改到
    契约测试。
- **`sandbox`** —— 执行沙箱的**档位语义**与**后端协议**。硬规则：
  - **选不到满足档位的后端即拒绝，绝不降级**：降级会让「宿主声明的强度」与
    「实际执行的强度」之间没有信号，档位整套机制就成了装饰。
  - **档位序即强弱**：要求档位是下限，满足下限者取**最弱**（够用且最省）。
  - **档位是后端自报的，本包不校验其真实性**：宿主若不信任某后端，唯一的办法
    是不登记它——本包不假装能验证隔离强度。
  - **兜不住预算的后端即不被选中**：档位（能力面）与支持面（资源兜底兑现哪几项）
    是**两个正交维度**——进程内解释器的能力面与 LevelProcess 同级，却兜不住内存。
    要求了而兜不住的后端**不被选中**（不是选中后失败）：前者是装配期判定，
    后者要等执行期才暴露。
  - **不实现 `Capable` 即只兑现基本三闸**（含**不兑现内存**）：缺省语义落在
    **保守的一侧**——漏声明得到的是「兜不住」，不是「兜得住」。方向与安全语义一致。
  - **`Provider` 不得加方法**：它已在 v0.9.0 发布，加方法是破坏性变更。能力扩展走
    **可选接口**（`Capable`），既有实现编译期零改动。
- **`wire`** —— 跨进程调用协议（`sandbox/wire`）。硬规则：
  - **协议只有一份**：后端只实现「怎么起这个进程」与「怎么执行这个程序」，
    帧格式与请求/响应语义一律用本包。协议各写一遍 ⇒ 换个后端就得换一套。
  - **失败分类跨进程同源**：`kind` 取 `toolfail` 的分类，**不得**退化成自由字符串
    ——分类一旦退化成字符串，父侧就分不清「可重试」与「永久拒绝」，重试策略随之
    瞎掉。`toolfail` 与 `sandbox` 同在本仓，**同层引用，无跨仓依赖**。
  - **预算的权威在父侧**：调用数与输出字节数由父侧记账。子进程自己记账可以
    **谎报**自己没超预算。
  - **在途调用有硬上限**：总量预算（MaxCalls）拦不住「瞬间发起十万次并发调用」
    ——那时它们都还没返回，父侧已被 goroutine 淹没。超出即回「超限」帧，
    **不排队等**（排队等就等于没有上限）。
  - **取消传播靠管道关闭**：父侧 ctx 取消 → 关连接 → 子侧读到 EOF → 在途全部失败。
    不需要单独的取消帧——**管道关闭本身就是最强的取消信号**。
  - **帧格式用长度前缀不用行分隔**：工具输出可能含换行，行分隔会被内容切断。
  - **版本不匹配即响亮失败**：静默错配的症状是「字段读成了另一个意思」——那是最
    难查的一类。
  - **启动通道与调用通道必须是两条连接**：共用一条则「读到的这帧是 Start 还是
    Response」只能靠猜——两者 JSON 形状不同（Start 有 program/bindings，
    Request/Response 有 tool/id），猜错的后果是「字段读成了另一个意思」。
    故四个角色各给一个类型：父 `Starter`/`Server`、子 `Runner`/`Client`。

### 错误处理

- 一律使用 `github.com/oekit/pkg/errors`；业务错误用 BizError。
- 所有 error 禁止 `_` 忽略。**安全相关路径尤其禁止吞 error** —— 判定失败必须阻断而非放行。

### 日志

- 本仓**不引日志依赖**。审计留痕在 `github.com/oagentkit/obs/audit`（那里引 logx）。
- 日志必须经 `logredact` 打码后再落，**不得直接打印原始载荷**。
- 审计走 `audit.New(log, service)`；`log` 为 nil 时回退 `logx.NewAuditLogger`
  （级别锁 `Info`，不受 `LOG_LEVEL` 降级 —— 这是刻意的，别改回普通 logger）。

### 并发安全

- 禁止裸 `go func`：用 `github.com/oekit/concurrency/async` 的 GoSafe 系列。
- 许可判定链若持有状态，必须有 `-race` 回归测试兜底。

### API 设计

- 函数选项模式命名 `XxxOption`（禁止裸 `Option`，多包 co-import 会冲突）。
- 导出符号 PascalCase + godoc 注释；包文档放 `doc.go`。

### 发版顺序

本仓的 `CHANGELOG.md` 由 `matrix-tools/scripts/gen_changelogs.py` 从 git 历史生成，
**不要手改**。发版顺序的**单一副本**见 org 规则仓
[CONTRIBUTING §发版](https://github.com/oagentkit/.github/blob/main/CONTRIBUTING.md#发版)：
**预写待发版段 → 提交 CHANGELOG.md → 在那个提交上打 annotated tag**。
tag 必须落在 CHANGELOG 提交**之后** —— 下游 `go get` 拿到的是 tag 快照，
快照里的 CHANGELOG.md 若缺自己那一段，发布说明就是残缺的。

⚠️ 无参重生成 CHANGELOG 会**吞掉待发版段**：生成器只按已存在的 tag 切段，
`--next-version` 是唯一能产出待发版段的开关。**预写之后、打 tag 之前，
不要跑无参重生成。**

本仓已有 4 个 CHANGELOG-at-tag 欠账（`guardx@v0.6.0`/`v0.7.0`/`v0.8.0`/`v0.8.1`，
清单见 `matrix-tools/scripts/changelog_tag_debt.json`）—— **反面例子，不是范例**；
另：`audit/v0.1.0`/`bashguard/v0.1.0` 是已冻结的嵌套子模块线，**不是本仓版本线**。

## 明确不属于本仓的

| 能力 | 归属 |
|---|---|
| 子进程最小环境 / 执行封装 | `github.com/oagentkit/runtime/procx` |
| 并发/流控/事件总线 | `github.com/oagentkit/runtime` |
| 熔断 | `github.com/oekit/concurrency/breaker`（`runtime/breaker` 已于 runtime v0.3.0 退役） |
| 工具优先级与并发调度 | `github.com/oagentkit/toolgate` |
| 通用 errors/stringx/encoding/mathx | `github.com/oekit/pkg` |
