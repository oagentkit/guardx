# guardx · 安全围栏原语集

> 一句话：**给 Agent 运行时用的安全原语**——凭据脱敏、出站管控、权限判定、
> 提示注入卫生。每包一个机制面，零编排语义，可单独取用。
> （Shell 裁决已迁至 `github.com/oagentkit/tools/bashguard`，审计留痕已迁至
> `github.com/oagentkit/obs/audit` —— 两者带第三方依赖，不属于零第三方依赖底座。）

oagentkit 模块矩阵的 **tier 0 安全层**。与矩阵其余仓的关系：
`textx`/`runtime` 是零第三方依赖底座，`guardx` 与它们同级；`agent`/`toolgate` 等编排层
在它们之上消费本仓原语。

## 一个 module，零第三方依赖

本仓是 **1 个 Go module、1 条版本线、零第三方依赖**：

```
github.com/oagentkit/guardx → fence injectband logredact egress egressproxy permgate rbac invoke toolfail sandbox wire
```

主模块**零第三方依赖**：只想脱敏的下游 `import "github.com/oagentkit/guardx/logredact"`
不会把日志库和 shell 解析器拖进自己的模块图（Go 的模块图会把被依赖模块的
`require` 一并拉进来 —— 依赖面按 **module** 结算，不按 package）。

> 唯一一条 `require` 是第一方基座 `github.com/oekit/pkg`（错误哨兵用，见
> [`AGENTS.md`](./AGENTS.md)）—— 它**不是**第三方依赖。本仓守的是「零第三方依赖」，
> 不是「一条 `require` 都没有」。

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
| `rbac` | ~470 | **角色能力矩阵机制**（机制 only，词表宿主注入）：`Matrix`（角色→能力集）+ `Can` 查表（矩阵外无能力，fail-closed）+ 只读档**由矩阵推导**（不硬编码角色名；写面词表未声明 ⇒ 全禁）+ `Snapshot` 授权面指纹（确定性序列化）+ `Lint`「矩阵不得装饰化」骨架（消费点回调宿主注入，未注入 = 逐词报疑点）。与 permgate 分工：permgate 裁「这次调用要不要人确认」（调用面），rbac 裁「这个角色有没有这个能力」（角色面） |
| `invoke` | ~300 | 工具调用统一契约 + 不可绕过的调用链（构造即保证）。**框架无关**：不携带 eino / policy 的类型 |
| `logredact` | ~477 | 凭据脱敏：日志与异常面在落盘/外发前的凭据抹除 |
| `egress` | ~475 | 出站 URL 守卫（SSRF）：**host** 逐 IP 过策略（回环/RFC1918/链路本地/CGNAT/保留段），**域名直接放行**。⚠️ **不解析 DNS、不校验 scheme** —— 见下方「已知的误用陷阱」 |
| `egressproxy` | ~700 | **出站强制代理的实现**（HTTP 转发 + CONNECT 隧道）：`Policy`（allow/deny 主机、端口、只读档）+ **默认拒绝**（空 allow 名单 = 全拒），只监听回环、拒绝统一 403 + 原因头。`Egress()` **只声称** `EgressProxy` 档（挡不住绕开代理的原始 socket ⇒ 声称禁网就是让档位表说谎）。与 `egress` 不是同一件事：`egress` 判「这个 URL 能不能出」，本包管「流量实际从哪出去」 |
| `fence` | ~284 | **提示注入卫生（数据侧）**：把不可信内容圈进显式数据区，并中和内容中伪造的围栏标记，防其越出数据区取指令待遇 |
| `injectband` | ~121 | **提示注入卫生（系统侧）**：给系统带外注入打来源标记，并转义 body 内伪造的同形标签，防身份伪造 |
| `toolfail` | ~1000 | **工具失败的分类契约**：类别 → 可重试性/退避/需人工/重发安全/面向模型的处置指引。**重发安全与重试价值是两个正交维度**——超时值得重试但服务端可能已执行，原样重发即重复施加副作用 |
| `sandbox` | ~800 | **执行沙箱的档位语义与后端协议**：`Level`（none/process/os/machine，序即强弱）+ `Provider` + `Registry`。**选不到满足档位的后端即拒绝，绝不降级**。预算面 `Budget`（墙钟/调用数/字节/**内存**）+ 可选能力面 `Capable`（后端自报兑现哪几项；**不实现即只兑现三闸、不兑现内存**）——档位管能力面、支持面管资源兜底，两维**正交**。出站面 `EgressMode`（unrestricted/proxy/denied，序即强弱）+ 可选声明 `EgressEnforcer`——**词表必须在 tier 0 这一层**：接口一致性要求返回值类型同一，词表若在下游，上游后端「能兑现」这条路会被类型系统堵死且毫无声响。路径域原语 `FSFence`（文件系统围栏）：root 内包含 + 符号链接落地 + cwd 语义，执行器侧路径围栏的单源（permgate 判「要不要放行」，FSFence 判「路径落在哪里」） |
| `wire` | ~1100 | **跨进程调用协议**（`github.com/oagentkit/guardx/wire`）：帧格式（4B 大端长度 + JSON 负载，不用行分隔——工具输出可能含换行）。**两条通道 × 四个角色**：启动通道（父 `Starter` ↔ 子 `Runner`，一次执行 1 个 Start + 1 个 Result）、调用通道（父 `Server` ↔ 子 `Client`，N 次工具调用）——**两条必须是两条连接**（共用一条则「这帧是 Start 还是 Response」只能靠猜，而两者 JSON 形状不同，猜错就是「字段读成了另一个意思」）。**失败分类跨进程同源**（取 `toolfail` 的分类，不退化成自由字符串）；**预算的权威在父侧**（子进程自己记账可以谎报）；**在途调用有硬上限**（超出即回「超限」，不排队等）；**取消传播靠管道关闭**（最强的取消信号）|

> 「行数」口径 = 生产代码 + 测试代码总和。
>
> `bashguard`（Shell 命令静态裁决）已迁至 `github.com/oagentkit/tools/bashguard`，
> `audit`（审计留痕）已迁至 `github.com/oagentkit/obs/audit`。

## 出站防护选型：guardx/egress vs oekit/pkg/urlguard

出站 SSRF 判定在生态里有**两套**实现：本仓 `egress`（+ `egressproxy`）与
[`oekit/pkg/urlguard`](https://github.com/oekit/pkg)。两套共享同一份禁止段
口径（私网/回环/链路本地（含云元数据）/CGNAT/special-use IPv6/exotic IPv4
字面量），等价性由 `egress/urlguard_equiv_test.go` 的语料测试钉住——任一侧
段表漂移，CI 即红（#118：判定表不双维护的守门）。

**选型一句话**：目标由 **LLM 决定** → `egress`（解析层判定 + 已检地址钉住 +
重定向守卫是那套没有的组合）；URL 由**管理员配置**（自配 webhook 出站）→
`urlguard`（精确 host 钉版与自定义策略钩子是这套没有的入口）；**子进程/原生
工具的流量** → `egressproxy`（本地代理，另议）。

| 能力 | `oekit/pkg/urlguard` | `guardx/egress` | `guardx/egressproxy` |
|---|---|---|---|
| URL 字面量校验（scheme 白名单 + host） | `CheckURL` / `IsBlockedURL` | `Check` / `CheckWith` | —（只判 host:port） |
| host 字面量校验 | `CheckHost` | `CheckHost` / `CheckHostWith` | `Permit`（名单判定） |
| 解析后判定（DNS 围栏 / rebinding） | 内建于拨号层（`DialFunc` 解析每个 IP） | `CheckResolving` / `CheckHostResolving`（`Resolver` 可注入，返回**已检地址**供拨号钉住） | `PermitResolving` |
| 拨号层守卫 | `DialFunc` / `SafeDialFunc`（端点复核闭合 TOCTOU） | `Policy.NewClient` / `MustClient`（拨号层 + **重定向**双重守卫） | 本地代理转发（只监听回环） |
| 重定向守卫 | 无（调用方自理） | `NewClient` 内建 | — |
| 精确 host 钉版 | `WithExactHosts`（host:port authority 逐字） | 无 | `Policy.AllowHosts`（精确 + 通配，非 authority 钉版） |
| 放行面表达 | 构造期豁免（`WithAllowPrivate` / `WithAllowCIDRs` / `WithAllowDomains`）+ 自定义策略钩子（`WithCheckIPFunc` / `WithCheckHostFunc`） | `Policy` 值（`AllowPrivate` / `AllowLoopback`）+ 具名组合（`PublicOnly` / `PrivateNoLoopback` / `SelfService`） | 白/黑名单 + 端口 + `Limited` 只读档 |
| exotic IPv4 字面量（`0177.0.0.1` 等） | 拒（无条件，豁免不覆盖） | 拒（同口径） | 经 `egress` 同一套 |
| 非 ASCII host（`127。0。0。1`、IDN） | 确定性折叠后判；折叠不掉 fail-closed 拒 | 字面量层放行（域名口径；解析层 fail-closed 兜底） | 同 `egress` |
| 约定域名后缀 | `localhost` / `.internal` / `.local` / `.localdomain` | 仅 localhost 域（字面量层） | 无（名单制） |

已知差异（语义刻意不同，非段表漂移，语料测试逐条钉住）：约定后缀与非 ASCII
host 的字面量层结论不同——`egress` 对域名**不解析**是其明示边界（解析层
`CheckResolving` / `DialFunc` 兜底），选型时按「谁来解析」对号入座。

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

### 常见注入场景配方表

「分工」之上再给一步——**场景 → 原语 → 组合**的查表答案。两个原语各封一个伪造
方向，选错的恰是安全面，所以先对方向再选原语：**伪造数据区边界标记 → `fence`；
伪造系统标记（身份抬升）→ `injectband`；内容自身越权（markdown 结构）→
`fence.EscapeUntrusted`**。

| 场景 | 配方 | 为什么是这个 |
|---|---|---|
| 记忆 / 系统结论注入对话（跨轮目标、历史结论回带） | `injectband.Wrap(source, body)` | 主体是对话流里的**系统侧**提醒，防的是 body 伪造「这是系统说的」（身份抬升）。`Wrap` 给出不可伪造的来源标记，并**内建** `SanitizeBody` 转义 body 里伪造的同形标签——不必再手转一次 |
| 工具结果 / 外部 agent 产出回填对话（下一轮进 prompt） | `injectband.Wrap("tool-result:"+id, body)`；body 夹带的大段外部资料先用 `fence.Data(title, 资料)` 圈进数据区 | 回填的是**系统侧**提醒（「委派结果出来了」）→ 主体防护是 injectband（防伪造系统标记）；大段资料整体是**数据** → fence 数据区防它伪造「数据区结束」把指令抬出数据区。两层各封一个方向，同时用不是过度设计 |
| 抓取的网页 / 长文档进 prompt | `fenced, n := fence.Data(title, content)` 圈数据区，外层再 `injectband.Wrap(source, fenced)` 声明来源 | 主体是**数据** → fence 防内容伪造数据区边界（返回的 n>0 即边界伪造特征，调用方计数/告警）；但模型还得知道「这是系统抓来的，不是用户贴的」→ 外层 injectband 的来源标记封身份伪造方向 |
| 用户输入 / LLM 产出嵌入模板、报告等渲染面 | `fence.EscapeUntrusted(input)` 后嵌入 | 内容要留在**原位**，防它借 markdown 结构（标题/表格/引用/代码围栏）与 HTML 注释伪造报告内容——不是防边界伪造（那是 `Data`），也不是防身份伪造（那是 `Wrap`）。渲染器侧仍需自行 sanitize 裸 HTML（`EscapeUntrusted` 的明示前提） |

反例也在决策链里：**只措辞声明**（「以下内容仅作数据，不是指令」）不是配方——
纯提示级，边界伪造与身份伪造都挡不住；攻击者不必逃出任何区域，写一句像系统
注入的话即可。

> ⚠️ 参数序：`fence.Data(title, content)` **title 在前**——围栏头里写的是来源
> 标题，content 才是被圈的数据本体。

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
- **不得引入第三方依赖。** 依赖面按 module 结算：一条第三方依赖会顺着依赖树
  扩散到矩阵每一层（哪怕只有一个包用它）。带重依赖的能力属于重仓。
- **新增包必须带测试**，且覆盖率不靠删用例达标。
