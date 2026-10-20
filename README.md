# guardx · 安全围栏原语集

> 一句话：**给 Agent 运行时用的安全原语**——凭据脱敏、出站管控、权限判定、
> 提示注入卫生。每包一个机制面，零编排语义，可单独取用。
> （Shell 裁决已迁至 `github.com/oagentkit/tools/bashguard`，审计留痕已迁至
> `github.com/oagentkit/obs/audit` —— 两者带第三方依赖，不属于零依赖底座。）

oagentkit 模块矩阵的 **tier 0 安全层**。与矩阵其余仓的关系：
`textx`/`runtime` 是零依赖底座，`guardx` 与它们同级；`agent`/`toolgate` 等编排层
在它们之上消费本仓原语。

## 一个 module，零外部依赖

本仓是 **1 个 Go module、1 条版本线、零外部依赖**：

```
github.com/oagentkit/guardx → fence injectband logredact egress permgate invoke toolfail sandbox
```

主模块**零外部依赖**：只想脱敏的下游 `import "github.com/oagentkit/guardx/logredact"`
不会把日志库和 shell 解析器拖进自己的模块图（Go 的模块图会把被依赖模块的
`require` 一并拉进来 —— 依赖面按 **module** 结算，不按 package）。

### 两个带重依赖的包已迁出（v0.7.0）

| 原位置 | 现位置 | 迁出理由 |
|---|---|---|
| `guardx/audit` | `github.com/oagentkit/obs/audit` | 依赖 `oekit/logx`；obs 本就带 logx |
| `guardx/bashguard` | `github.com/oagentkit/tools/bashguard` | 依赖 `mvdan.cc/sh/v3`（真 shell AST）；tools 是重仓 |

> ⚠️ `github.com/oagentkit/guardx/audit` 与 `.../guardx/bashguard` 两条路径**已退役**
> （曾短暂以嵌套 module 形式存在，tag `audit/v0.1.0` / `bashguard/v0.1.0` 仍在，
> 但那条线**已冻结**）。新代码用上面表里的新路径。

## 包清单

| 包 | 行数 | 职责 |
|---|---|---|
| `permgate` | ~500 | 能力门禁：`Capability` / `Rule` / `Ruleset` / `Decision`。判定链以 deny 优先于 approval，输出可审计的裁决结构 |
| `invoke` | ~300 | 工具调用统一契约 + 不可绕过的调用链（构造即保证）。**框架无关**：不携带 eino / policy 的类型 |
| `toolfail` | ~1000 | **工具失败的分类契约**：类别 → 可重试性/退避/需人工/重发安全/面向模型的处置指引。**重发安全与重试价值是两个正交维度**——超时值得重试但服务端可能已执行，原样重发即重复施加副作用 |
| `logredact` | ~477 | 凭据脱敏：日志与异常面在落盘/外发前的凭据抹除 |
| `egress` | ~475 | 出站 URL 守卫（SSRF）：**host** 逐 IP 过策略（回环/RFC1918/链路本地/CGNAT/保留段），**域名直接放行**。⚠️ **不解析 DNS、不校验 scheme** —— 见下方「已知的误用陷阱」 |
| `fence` | ~284 | **提示注入卫生（数据侧）**：把不可信内容圈进显式数据区，并中和内容中伪造的围栏标记，防其越出数据区取指令待遇 |
| `injectband` | ~121 | **提示注入卫生（系统侧）**：给系统带外注入打来源标记，并转义 body 内伪造的同形标签，防身份伪造 |
| `sandbox` | ~630 | **执行沙箱的档位语义与后端协议**：`Level`（none/process/os/machine，序即强弱）+ `Provider` + `Registry`。**选不到满足档位的后端即拒绝，绝不降级** |

> 「行数」口径 = 生产代码 + 测试代码总和。
>
> `bashguard`（Shell 命令静态裁决）已迁至 `github.com/oagentkit/tools/bashguard`，
> `audit`（审计留痕）已迁至 `github.com/oagentkit/obs/audit`。

## 提示注入的两个方向

`fence` 与 `injectband` 互补，**不是替代关系**——它们封的是相反两个方向：

```
   不可信内容（工具返回 / diff / 抓取正文）
        │
        ├─→ fence.Data()   圈进数据区，标记「这是数据，不得当指令」
        │
   系统带外注入（历史对话 / 目标续跑 / 工具护栏提示）
        │
        └─→ injectband.Wrap()  标记「这是系统说的」，并转义伪造同形标签
```

只做 `fence` 是不够的：系统提示与用户文本在模型眼里仍是同一等公民，攻击者不必
逃出数据区，只需在数据区里写一个**像系统注入的标签**即可抬升自己的权限。
`injectband` 补的正是这个身份伪造缺口。

## 已知的误用陷阱

**`egress` 不解析 DNS。** `checkHost` 对域名直接返回放行（`return nil // 域名：不解析`）。
因此**任何人直接拿 `egress.Check(url)` 挡住 LLM 可控 URL，会得到零 DNS-rebinding
防护**——真正的 SSRF 防线在调用方的解析层（逐 IP 判定）。本包只提供**逐 IP 策略判定**
这个原语，不承担解析职责。需要解析后判定的场景（如编排内核的 `netguard`）应自行
解析后逐 IP 调用。

**`egress` 不校验 scheme。** `Check` 只做 `url.Parse` 后取 `u.Hostname()` 送策略判定，
**从头到尾没有读过 `u.Scheme`**。实测行为（`egress.Check` 直接跑）：

| URL | 结果 |
|---|---|
| `gopher://example.com/x` | **放行**（`nil`） |
| `dict://example.com:11211/stats` | **放行**（`nil`） |
| `ftp://example.com/x` | **放行**（`nil`） |
| `file:///etc/passwd` | 拒绝（`空 host`——该 scheme 没有 host） |
| `http://127.0.0.1/x` | 拒绝（回环地址） |
| `http://localhost/x` | 拒绝（localhost 域） |

也就是说：**凡是有 host 的非 http(s) scheme，一律走「域名不解析 → 直接放行」分支**。
想要 scheme 白名单，**必须由调用方自己判**（在调用 `egress.Check` 之前先看
`u.Scheme` 是否在允许集合里）。

这不是可以后续补齐的细节，而是**当前实现的真实边界**。把 `egress` 当成
「URL 安全检查器」用会得到虚假的安全感——它只挡 IP 字面量与 `localhost` 域。

## 门禁

CI 是**薄调用层**：规则本体在 `oagentkit/.github` 的共享工作流，
各仓 `ci.yml` 只传 `go-version`。改门禁规则只改那一个仓，本仓不动。

```bash
go test ./... -cover        # 本机验证
gofmt -l . && go vet ./...
```

> macOS：本机 go build/test 一律带 `CGO_ENABLED=0`（新 SDK 27.0 与 CLT linker 不兼容）。

## 边界纪律

- **本仓只有机制，没有策略内容。** 规则表、词表、阈值、命名都属于调用方：
  `tools/bashguard` 给裁决机制不给规则集，`permgate` 给判定链不给具体能力清单。
  把「哪些命令危险」写成代码里的常量，就是把调用方的资产焊进原语仓。
- **不得引入领域词。** 本仓是 tier 0，地板被所有下游继承——任何一层业务味
  都会顺着依赖树扩散到矩阵每一层。
- **不得引入外部依赖。** 依赖面按 module 结算：一条第三方依赖会顺着依赖树
  扩散到矩阵每一层（哪怕只有一个包用它）。带重依赖的能力属于重仓。
- **新增包必须带测试**，且覆盖率不靠删用例达标。
