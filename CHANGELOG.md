# guardx CHANGELOG

> 本文件由 `matrix-tools/scripts/gen_changelogs.py` 从 git 历史生成，按 tag 切段、取每段内的 conventional commit 渲染。

## [v0.15.0] — 2026-10-24

### 新增(egress)：具名放行面 Policy + 拨号层胶水 NewClient/MustClient

issue #28：egress 只导出 Options 的两个 bool 位，调用方要现场拼放行面，
下游各自手搓拨号层胶水——同一份「私网放行 + 回环拒」的语义在多个仓里各写一遍，
值传岔就出两种故障：校验层放行私网、拨号层按缺省拒（假红）；校验层拒、拨号层放行
（安全问题）。
改动：
- 新增 Policy（放行面本体，带 Check / CheckHost 方法）；
- Options 收敛为兼容别名（type Options = Policy）——既有调用点逐字编译通过，
  同一个类型而不是两套并行表示；
- 新增具名放行面 PublicOnly（= 零值，与 Check/CheckHost 的缺省口径一致）/
  PrivateNoLoopback / SelfService；
- 新增 Policy.NewClient / Policy.MustClient：把同一份放行面落到
  http.Transport 的拨号层，判定与写面共用同一个字面量判定函数，
  且发生在拨号之前（被拒的地址不会被连上）。
取舍：拨号层刻意不做「连上之后核对实际对端地址」——那会让拨号层比写面更严
（写面放行域名、拨号层拒它的解析结果），两层口径就不一致了，正是本改动要
消灭的形态。解析层防护仍由消费方按需叠加（与包既有口径一致）。
拨号层多出来的价值：重定向（http.Client 默认跟随重定向，写面只校验了最初
那个 URL，真正被拨号的是重定向目标）与漏调写面校验的调用方。
兼容性：公共 API 只增不改（Options 仍是导出 type，只是变成别名）；
不新增任何依赖（本仓 tier 0，require 段不变）；
门面 agentkit/egress/alias.go 需补 4 个转发，随门面发版一起做。
门禁自检：go build ✅ / go vet ✅ / go test -race ✅ 9 包全绿 /
go mod tidy -diff ✅ / gofmt ✅ / golangci-lint 0 issues ✅ /
覆盖率 egress 92.1%、全模块 95.3%（阈值 30%）。
反证样本——回退「不挂拨号守卫」3 条测试红；回退「先连后判」1 条测试红
（dialed=[127.0.0.1:62576]），非编译层。

- 杂务(deps)：oekit/pkg 依赖地板抬到 v0.22.1

矩阵的**发版时刻地板门禁**（`verify_tag_floor`）要求：打 tag 那一刻的依赖地板
必须是当时的最新。guardx 钉在 `oekit/pkg v0.22.0`，而基座已于 2026-10-24T02:17
发布 `v0.22.1` ⇒ 本仓 HEAD（2026-10-22T17:46）之后一旦有新的 push，
地板就会变成「出生即落后」——tag 受 `protect-tags` 保护**不可重打**，
只能记进 `tag_floor_debt.json` 欠账基线。
## 零行为差异的实证
本仓只用 `oekit/pkg/errors` 的 4 个函数（New / As / Is / Wrap）。实测两版之间
该包**逐字未改**：
```
$ git diff --stat v0.22.0 v0.22.1 -- errors/
（空输出）
```
v0.22.1 的新增全在别处（`urlguard` 的 CIDR / 域名放宽位与配套测试，
外加文档），本仓一行都不 import ⇒ 纯地板追平，**零行为差异**。
## 改动面
`go.mod` 1 行版本号 + `go.sum` 2 增 2 删。
门禁自检：go build ✅ / go vet ✅ / go test -race ✅ 9 包全绿 /
go mod tidy -diff ✅ / gofmt ✅。


## [v0.14.0] — 2026-10-22

### 修复(permgate)：只读档对写入类工具是「禁」不是「问」

issue #24：只读模式 + 危险工具拿到的是 Ask（＝问一句），与「拒」语义相反——
只读档的意义正是「不给问的机会」，否则只读退化成「换个姿势问」。
根因不是「表达不了」，是**实现与本仓自己的分段文档相矛盾**：
包注释第 13 行写的就是「只读模式 → 只读工具放行、其余拦下」，只读段
（permgate.go:175-179）本身返回的也已经是 Deny——只是两处更早的「问」
把它短路成了 Ask：
  - checkAlwaysAsk（:138）全程不看 mode，alwaysAsk 工具在只读档落 Ask；
  - checkStandard（:165）里 project ask（:173）排在只读段（:175）之前。
改法：新增只读拦截段（readonlyWrite / readonlyDeny，单源），插在
  - checkStandard：project ask 之前；
  - checkAlwaysAsk：会话授权之后、ask 之前。
既有分段的相对顺序未变（插入而非调换）；RuleID / Reason 与原只读段逐字
相同（mode.read_only / 只读模式拦下写入: X）⇒ 审计口径不变，按 RuleID
聚合的既有消费方不受影响。
公共 API 零变更：不新增导出符号，不改 Capability / Mode / Ruleset /
Service 形态 ⇒ 门面 agentkit/permgate/alias.go 无需跟进。
有意不改的边界（详见 issue #24 评论）：
  - 会话授权在只读档仍放行（是用户已经给出的决定，不是「问」；本仓既有
    语义「会话授权段 → 命中即放行，不看模式」）；
  - 交互型工具在只读档仍 Ask（不产生副作用，plan 档要靠它向用户提问）；
  - 默认档不变（危险工具在 default 档仍是 Ask）。
门禁自检：go build ✅ / go vet ✅ / go test -race ✅ 9 包全绿 / gofmt ✅ /
go mod tidy ✅。反证样本——回退实现后新测试红在断言上（3 处），非编译层。

- 杂务(deps)：oekit/pkg 依赖地板抬到 v0.22.0

矩阵的发版时刻地板门禁（verify_tag_floor）要求：打 tag 那一刻的依赖地板
必须是当时的最新——guardx 钉在 v0.20.0，而远端最新已是 v0.22.0。
不先抬地板就打 tag，产出的就是「出生即落后」的 tag（tag 受 protect-tags
保护，不可重打）。
本仓只用 oekit/pkg/errors 的 4 个函数（New / As / Is / Wrap），实测
v0.20.0 → v0.22.0 之间该包**逐字未改**（git diff --stat v0.20.0 v0.22.0
-- errors/ 输出为空）；两版的新增全在别处：
  - v0.21.0：pathx.SanitizeFileName
  - v0.22.0：pathx.MatchGlob、pathx.IsSafeFileName、stringx.SplitCSVNonEmpty
故这是纯地板追平，零行为差异。
改动面：go.mod 1 行版本号 + go.sum 2 增 2 删。
门禁自检：go build ✅ / go vet ✅ / go test -race ✅ 9 包全绿 / gofmt ✅ /
go mod tidy ✅


## [v0.13.1] — 2026-10-21

- 杂务(deps)：oekit/pkg 依赖地板抬到 v0.20.0

本仓只用 oekit/pkg/errors 的 4 个函数（New / As / Is / Wrap），它们在
v0.18.0 → v0.20.0 之间是同型透传（New 是 stdlib 的 shim，As/Is 是
stdlib 透传，Wrap 是 nil-safe 的包装）——故这是纯地板追平，无行为差异。
矩阵的依赖地板时效门禁（verify_dep_floors.py）会把它报出来；该门禁在 CI 上
是报告模式（continue-on-error），不阻断合并，但漂移清单应尽量干净。
门禁自检：go build / vet / test ✅ 9 包全绿，gofmt ✅，go mod tidy ✅


## [v0.13.0] — 2026-10-21

### 修复(wire)：wire 移到仓根——矩阵的包路径规则不支持仓内包的子包

## 为什么要移
矩阵的**包路径唯一构造规则**是「`github.com/{org}/{repo}/{包名末段}`，中间层目录丢弃」
（matrix-tools/scripts/matrix_paths.py 的 new_import_path）。故：
- `llm/port` 的 importPath 是 `github.com/oagentkit/llm/port`——它在 **llm 仓根下**
  （`llm/port/`），`llm/` 只是旧单仓的组织目录残留；
- 而 `sandbox/wire` 若留在 `guardx/sandbox/wire/`，importPath 就是
  `github.com/oagentkit/guardx/sandbox/wire`——**与规则冲突**（规则要求
  `github.com/oagentkit/guardx/wire`）。
矩阵的模型是「一个仓 N 个**平级**包」，不支持「仓内包的子包」。而 guardx 的
`sandbox` 本身已是一个平级包，`sandbox/wire` 就成了它的子包。
## 实证
移之前 matrix-tools 的 import 路径对账门禁报红：
    ❌ guardx/wire: 矩阵登记了这个包，仓里却没有对应的 .go 目录
（该门禁只扫仓根下一层的包目录——嵌套第二层的目录它看不到。）
## 改动
- `sandbox/wire/` → `wire/`（git mv，保留历史）
- AGENTS.md 目录清单、README 包表同步
import 路径随之从 `github.com/oagentkit/guardx/sandbox/wire` 变为
`github.com/oagentkit/guardx/wire`——**这是 breaking**（公开 API 路径变更），
但 wire 才刚发版（v0.11.0 / v0.12.0），下游尚未接入，此刻改代价最小。
## 门禁

## [v0.12.0] — 2026-10-21

### 新增(wire)：补齐执行生命周期——Start / Result 帧与「两条通道 × 四个角色」

v0.11.0 的 wire 只覆盖了「子→父的工具调用」，**缺一次执行的启动与收尾**：
父侧怎么把「跑什么」告诉子进程、子进程跑完怎么回报结果，两帧都没有。
## 缺口
程序一旦出宿主进程，父侧要交给子侧三样东西：**程序体**、**绑定清单**（名字与
调用形态，不是实现——实现留在父侧，子侧通过调用帧请求执行）、**预算要求**。
子侧跑完要回报**结果**。
这两组信息走**不同的通道、不同的方向**：
    启动通道：父 Starter ←→ 子 Runner   （一次执行：1 个 Start + 1 个 Result）
    调用通道：父 Server  ←→ 子 Client   （N 次工具调用）
**两条通道必须是两条连接。** 若共用一条，「读到的这帧是 Start 还是 Response」
只能靠猜——而两者 JSON 形状不同（Start 有 program/bindings，Request/Response
有 tool/id），猜错的后果是「字段读成了另一个意思」，那是最难查的一类协议 bug。
实现过程中确实先试过「共用一条 + Client 上加 AwaitStart」——结果是
`Client.readLoop` 与 `AwaitStart` **争抢同一个读端**：响应帧被读循环当
Start 吃掉，启动帧被 AwaitStart 当响应吃掉，表现为测试挂死 90 秒。
这个「两条消费者抢一个 reader」的形态在真实部署里同样会发生，故拆成四个类型。
## 四个角色
| 角色 | 侧 | 职责 |
|---|---|---|
| `Starter` | 父 | 发 Start、等 Result；子进程被内核杀掉时**管道 EOF** ⇒ 报「执行域异常终止」（不是「程序返回空」） |
| `Runner` | 子 | 等 Start、回 Result |
| `Server` | 父 | 应答工具调用：并发处理 + 记账 + 在途限流 |
| `Client` | 子 | 发起工具调用，按 id 关联响应 |
## 新增两帧
- `Start`：程序体 + 绑定清单 + 预算要求 + 结果标识。
  绑定交的是**清单**不是**实现**——这正是跨进程的意义：宿主工具只在宿主进程里存在。
- `Result`：成败 + 分类（取 `toolfail` 的分类）+ 值 + 实际调用数/字节数（父侧对账）。
## 兼容性
- 既有 API 零改动（v0.11.0 刚发布，本扩展只**新增**类型与帧）；
- 不引入新依赖。
## 门禁
```
go build / vet / test -race   ✅ 9 包全绿
sandbox/wire 覆盖率            93.2%
全仓总覆盖率                  95.7%
gofmt -l .                    ✅ 空
golangci-lint                 ✅ 0 issues
```

## [v0.11.0] — 2026-10-21

### 新增(wire)：新增跨进程调用协议（sandbox/wire）

承接 #18（下游 agent-harness 侧的执行沙箱多后端需求）的 P1 上游部分。
## 缺口
档位（Level）答「能力面多强」，预算支持面（Capable）答「资源兜底兑现哪几项」——
但这两者都还缺一块：**程序一旦出宿主进程，工具回调就够不着了**。
进程内执行时 `host.<tool>()` 是一次普通 Go 函数调用；出宿主进程后它变成一次跨进程
IPC。这段 IPC 若由每个后端各写一遍，就有一堆互不兼容的私有协议——而协议恰恰是
最不该私有的东西。
## 交付
`sandbox/wire`：帧格式 + 父侧服务端循环 + 子侧客户端。
### 帧格式
长度前缀 + JSON（**不用行分隔**——工具输出可能含换行，行分隔会被内容切断）：
    ┌───────────────┬──────────────────────────────┐
    │ 4B 大端长度 N  │ N 字节 JSON 负载             │
    └───────────────┴──────────────────────────────┘
长度前缀是外部输入，故设上限（默认 16MB）——一个坏的长度前缀就能让接收方预分配
几 GB。
### 六条不变量（逐条有测试钉住）
1. **版本响亮失败**：`v` 不匹配即拒，不静默错配（错配的症状是「字段读成了另一个
   意思」——那是最难查的一类）。
2. **失败分类跨进程同源**：`kind` 取 `guardx/toolfail` 的分类，**不是**自由字符串。
   分类一旦退化成字符串，父侧就分不清「可重试」与「永久拒绝」，重试策略随之瞎掉。
   `toolfail` 与 `sandbox` 同在本仓——**同层引用，无跨仓依赖**。
3. **预算的权威在父侧**：调用数与输出字节数由父侧记账。子进程自己记账可以**谎报**
   自己没超预算。
4. **在途调用有硬上限**：总量预算（MaxCalls）拦不住「瞬间发起十万次并发调用」——
   那时它们都还没返回，父侧已被 goroutine 淹没。超出即回「超限」帧，**不排队等**
   （排队等就等于没有上限）。
5. **取消传播靠管道关闭**：父侧 ctx 取消 → 关连接 → 子侧读到 EOF → 在途全部失败。
   不需要单独的取消帧——**管道关闭本身就是最强的取消信号**。
6. **响应按 `id` 关联，不按到达顺序**：程序里多个 await 是并发的，返回顺序与请求
   顺序无关。
### 与设计档的一处偏离（须知）
设计档 §四 的落位表把交付写作「帧格式、类型化失败、`Transport`、父侧服务端循环、
子侧客户端」。**本实现没有独立的 `Transport`**，而是把它的职责并进了 `Server`：
理由是**方向**。程序在子进程里（`host.<tool>()` 由程序发起），故**子侧是发起方**
（`Client`）、父侧是应答方（`Server`）。若让父侧也当发起方（独立 `Transport`），
记账就会记在错误的一侧——配额该在**接受调用**时扣，不是谁发起谁扣。
实现过程中确实先写过一版 `Transport`（父侧发起 + 等响应），它的读循环几乎
测不到（正常路径不存在），正是这个方向错误的信号。故合并：`Server` 持有预算与
在途闸，`Client` 发起调用。
**父侧并发处理**（每个请求一个 goroutine）——否则「在途上限」永远触发不了，
而一次慢调用会阻塞其他全部调用。
## 兼容性
- 新增包，既有 8 个包的 API **零改动**；
- 不引入任何新依赖（主模块「零外部依赖、`go list -m all` 只有一行」的门禁不受影响）；
- `wire` 与 `toolfail` 同仓引用，无跨仓依赖。
## 门禁
```
go build / vet / test -race   ✅ 9 包全绿
sandbox/wire 覆盖率            95.0%
全仓总覆盖率                  96.3%
gofmt -l .                    ✅ 空
golangci-lint                 ✅ 0 issues
go mod tidy -diff             ✅ 无漂移
```
## 下游怎么用
后端实现方（如 agent-harness 的 ptc 子进程后端）：起进程、连两条管道
（请求方向与响应方向各一条）、跑程序；协议一律用本包的 `Server` / `Client`。
宿主只声明「要哪一档 + 哪些预算项」，不碰协议。

## [v0.10.0] — 2026-10-21

### 新增(sandbox)：预算面补 MaxMemory + 可选能力面 Capable

承接 #17（下游 agent-harness 侧的执行沙箱多后端需求）。
## 缺口
`Budget` 只有三项（墙钟 / 调用数 / 输出字节），**没有内存这一项** ⇒ 宿主**无从要求**
内存上限。而进程内解释器后端**兜不住内存**（Go 运行时没有「只给一个 VM 限内存」的
开关，解释器本身也没有内存限制 API）——于是「这组预算我兜不兜得住」这件事
**两端都说不出来**：一个兜得住的后端与一个兜不住的，在选择时长得一样。
后果不是理论上的：模型写的一段快速分配的程序，能在 deadline 到点**之前**把宿主进程
内存吃光，宿主被 OOM 杀掉——而宿主进程里还跑着编排引擎、事件总线、别的环节。
## 三处改动
### 1. `Budget` 补第四项
```go
MaxMemory int64 // 内存上限（字节）。0 = 不要求。
```
**为什么不新增一维 `Level`**：想加一维「资源兜底（Containment）」——子进程 + rlimit
这个后端在现有阶梯上无处安放：能力面是解释器白名单（同 LevelProcess），资源面是内核
兜底（更强），文件/网络面未裁剪（比 LevelOS 弱）——一维说不通。
但改用「兜底是**预算项**」之后，一维阶梯保持成立：`Level` 继续管**能力面**（安全
维度），**资源兜底**是正交的一维，而它**本来就有一个位置**——`Budget` 就是「这次执行
要多少资源」的载体，内存只是漏了第四个。
### 2. 新增可选能力面 `Capable`
```go
type Capable interface {
    Supports(b Budget) bool
}
```
**刻意是可选接口而不是 `Provider` 的新方法**：`Provider` 已在 v0.9.0 发布，
给它加方法是**破坏性变更**。可选接口让既有实现**编译期零改动**，且缺省语义天然
落在**保守的一侧**：
    不实现 Capable ⇒ 只兑现基本三闸、**不兑现内存**
    ⇒ 要求 MaxMemory 的请求不被选中 ⇒ fail closed
方向与安全语义一致：漏声明 ⇒ 少能力，不是多豁免。
另附 `CapableFunc` 适配器与 `SupportsBasic` / `SupportsAll` 两个常用实现，
让后端不必为一个判定写具名类型。
### 3. `Resolve` 按支持面过滤
```go
func (r *Registry) Resolve(min Level, budget ...Budget) (Provider, error)
```
**budget 是可选参数**：把 budget 加成必填参数是破坏性变更；可选参数让既有调用点
（`Resolve(min)`）**编译期零改动、行为逐字不变**——省略 budget 时只看档位，
与旧版一致。
兜不住预算的后端**不被选中**（不是选中后失败）：这与「档位不足」的处置同一条纪律，
但**成因不同、处置也不同**——档位不足可以「把要求降一档」，兜不住预算只能
「换执行模型」或「放弃这项要求」，降档解决不了它。
多组预算**逐项取要求更高者**（求和是配额语义，这里是上限语义）。
`Execute` 内部用 `req.Budget` 过滤——请求里的预算要求**同时用于选后端**，
否则「要求了内存兜底而后端兜不住」只在执行期暴露，而选后端这步本可以拦下它。
既有调用的 `req.Budget.MaxMemory` 是 0（新字段零值 = 不要求），故**行为逐字不变**。
## 兼容性
- `Budget` 加字段：源码兼容（无键字面量的用法需改，属极少数）；
- `Capable` 是**新增可选接口**：既有 `Provider` 实现零改动；
- `Resolve` 行为变化：**只影响「要求了 MaxMemory 而后端兜不住」这一种情形**——
  此前这种要求根本无从表达，故无行为漂移；
- 不引入任何新依赖（主模块「零外部依赖、`go list -m all` 只有一行」的门禁不受影响）。
## 验收
- 要求 `MaxMemory` 而候选后端不实现 `Capable` ⇒ `Resolve` 返回 `ErrNoProvider`
  （**不是选中后失败**）；
- 实现了 `Capable` 且返回 true 的后端被选中，且仍取**最弱**满足者；
- 既有 `Provider` 实现编译期零改动、行为逐字不变；
- `go list -m all` 仍只有本模块一行。
**下游实跑**：agent-harness（真实既有下游，其 `ptc` 就是不实现 `Capable` 的后端）
用本分支替换依赖后**编译零改动、全量测试全绿**——`ptc.Provider` 三个方法一个没动。
## 门禁
```
go build / vet / test -race   ✅ 8 包全绿
sandbox 覆盖率                100.0%
全仓总覆盖率                  96.7%
gofmt -l .                    ✅ 空
golangci-lint                 ✅ 0 issues
go mod tidy -diff             ✅ 无漂移
```

- 文档(AGENTS)：补「发版顺序」小节，指向 org CONTRIBUTING 单一副本

13 个业务仓的 AGENTS.md 此前对发版顺序零覆盖（只有 textx 有个
「### 版本与发版」标题，但里面只讲 SemVer 与 module 路径），
发版顺序只写在 org 规则仓的 .github/CONTRIBUTING.md 里，单仓读者看不到。
本次只加**指针 + 本仓相关提醒**，runbook 本体保持**单一副本**
（CONTRIBUTING §发版），避免 13 份副本各自漂移。
覆盖四条：
- CHANGELOG.md 由 matrix-tools/scripts/gen_changelogs.py 从 git 历史生成，不要手改
- tag 必须落在 CHANGELOG 提交之后（下游 go get 拿到的是 tag 快照）
- 警告：无参重生成会吞掉待发版段，--next-version 是唯一能产出待发版段的开关
- 本仓相关提醒（见正文）


## [v0.9.0] — 2026-10-21

### 新增(sandbox)：新增执行沙箱的档位语义与后端协议（自 agent-harness 下沉）

* feat(sandbox): 新增执行沙箱的档位语义与后端协议
自 agent-harness/sandbox 下沉。「模型写的程序在哪跑、跑起来能触达什么」
若只有一个写死的答案（进程内解释器），那么「它跑在够强的隔离里吗」就无处
声明——只能靠人记得别挑错后端。
本包把这件事变成可声明、可判定的机制：
- Level：隔离档位（none/process/os/machine），序即强弱；
- Provider：后端协议（自报提供哪一档，并执行程序）；
- Registry：登记簿，按「要求档位」选后端。
硬规则：
1. 选不到满足档位的后端即拒绝，绝不降级。降级会让「宿主声明的强度」与
   「实际执行的强度」之间没有信号，档位整套机制就成了装饰——差的那个量级
   就是全量暴露。故 Resolve 无满足者时返回 ErrNoProvider。
2. 要求档位是下限，满足下限者取最弱（够用且最省）。要求写低拿到弱后端是
   宿主自己的声明，不是门禁的失败。
3. 档位是后端自报的，本包不校验其真实性。宿主若不信任某后端，唯一的办法
   是不登记它——验证隔离强度需要审后端实现，不是判据能做的事。
与本仓 invoke 包的关系：invoke 管「一次工具调用要不要放行」（判定环），
本包管「一段被执行的程序跑在什么隔离档位上」（执行环境）。不同的执行点，
不要混成一条链——把本包做成 invoke 的一环需要猜「哪个参数字段是程序体」，
那是宿主知识。
为什么落 tier 0 安全层：invoke 包的立论之一是「信任边界移动了，沙箱没跟着
移动」，而它指出的正是缺少一个可声明的档位概念——此前只有「有没有沙箱」的
二元说法，没有「够不够强」的说法，于是隔离降级这类事故无法在装配期被发现。
零外部依赖（仅 oekit/pkg/errors）。sandbox 包覆盖率 100%。
* fix(sandbox): 档位序断言改成正向形式——过 staticcheck QF1001
CI 的 golangci-lint（staticcheck QF1001）判德摩根律形式可化简：
「!(a && b && c)」在 a、b、c 都是同向比较时，改成「a >= b || b >= c || c >= d」
的正向形式即可。断言语义不变：档位序必须严格递增。

### 新增(toolfail)：新增工具失败分类契约（自 agent-harness 下沉）

* feat(toolfail): 新增工具失败分类契约——类别/可重试/重发安全/面向模型的处置指引
自 agent-harness/toolfail 下沉。失败分类与处置判定是跨宿主一致的语义，
与编排无关，故归 guardx（tier 0，与 invoke/permgate 同族）。
三条硬规则：
1. 不可分类 = 不可重试（保守缺省）。退避重试的代价不对称：误判可重试
   是把一次失败放大成 N 次，还可能对有副作用的工具重复施加副作用。
2. 重发安全与重试价值是两个正交维度。超时多半值得重试，可服务端那边
   请求可能已经执行完毕，原样重发就可能把一次调用变成两次副作用。
   只看「可重试」的调用方必然在这两种误判里选一个。
3. 策略是数据不是 if 链。类别 → 处置的映射写进单源策略表，契约测试
   逐格钉住；改表必然改到测试。
分类路径四条且顺序不可调换：链上已有 *Failure（最具体）→ 错误自报
RetryableReporter（这次的实情）→ 哨兵集合 → unknown。第三条路径治的是
「判据本来就在，只是没人去问」：产出失败的那一层知道可重试与否，
不问就会落到 unknown，把可恢复的失败判成永久失败。
与 mcpkit/mcp.ErrorKind 的分工（互补，不重复）：后者判**协议层事实**
（连不上/协议错/工具不存在/参数错），本包判**处置层语义**（该不该重试、
能不能原样重发、要不要人工、模型下一步干什么）。协议层给不出后三个维度
——它不知道「这次调用是不是只读的」。
覆盖率 99.0%，全仓总覆盖率 96.2%。零外部依赖（仅 oekit/pkg/errors）。
* docs: 包清单同时登记 sandbox——与 #15 保持一致，消除合并冲突
两个 PR 都基于 main 改同一处包清单，若各自只登记自己的包，先合并者会
覆盖后合并者的登记。与其让上游 reviewer 手工解冲突，不如让两边的
包清单一致：合并后即为最终态，无冲突。
sandbox 包本身仍由 #15 提供，本提交只登记它的名字。
* docs: 包清单登记改由 #15 统一承担，本 PR 只含代码
两个 PR 都基于 main 改同一处包清单（README 表格行 + AGENTS.md 头部 +
硬规则段），逐字不同就会冲突——包清单表格的**行位置**也会导致文本冲突。
故本 PR 的文档改动回退到 main 原样，包清单与硬规则登记统一由 #15 承担
（它同时登记两个包）。这样：职责单一、合并零冲突、最终态一致。
toolfail 包本身在本 PR 中提供。

- 杂务(deps)：oekit 依赖地板抬到 v0.18.0

oekit 姊妹矩阵的依赖地板对齐到最新：
- github.com/oekit/pkg        v0.17.0 → v0.18.0
- github.com/oekit/concurrency v0.17.1 → v0.18.0
- github.com/oekit/logx       已是最新 v0.7.1，不动
oekit v0.18.0 的两个发布都是**纯增量**，无破坏性变更：
- pkg：jsonrepair 补抽数组原语 ExtractArray；
- concurrency：新增 `DoValue[T]`（带返回值的重试），`Do` 改为委托给它——
  退避序列、抖动、MaxDelay 封顶、DelayHint 优先、Retryable 门控、ctx 取消
  **只有一份实现**（此前这类调用方只能自己重写一遍退避，且常丢掉 DelayHint 语义）。
依据 oagentkit/matrix-tools#44 的还债流程：依赖地板对齐到发版时刻的最新。
本仓本轮不发 tag（不在发版集内），地板在 main 上就位，下次发版自然带上。


- 文档(changelog)：按新生成器规则重生成 CHANGELOG.md

生成器修复（oagentkit/matrix-tools#43）落地：
① `[round-N] ` 前缀被剥离 → conventional commit 解析不再失效，
   **commit body 保留**（此前整段被丢弃，发布说明只剩标题）；
② 非 conventional 提交也保留 body；
③ `--check` 识别「待发版段」（预写了但还没打 tag 的那段）。
本 PR 恢复的是**本就在 commit body 里**的正文（迁移步骤、代码块、
判据锚点）——此前被 `[round-N] ` 前缀导致的解析失败丢弃了。
**没有任何发布说明内容被删除**：删除的行都能在新增行里找到对应
（规范化掉 `(#N)` 与 `[round-N] ` 前缀后逐行比对）。
关联：oagentkit/matrix-tools#43、oagentkit/matrix-tools#40


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
