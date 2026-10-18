# AGENTS.md — AI 编码代理工作纪律（guardx）

本仓是 **tier 0 安全原语集**：只放机制，不放策略内容与领域知识。
这条边界靠纪律 + CI 双保险，AI 代理在本仓干活时最容易犯的错是
「顺手把调用方的规则表写进来」。

## 边界纪律（最高优先级）

- **新增任何代码前先判归属**：这是机制还是策略内容？
  - 机制（与「谁在用它」无关）→ 本仓；
  - 策略内容（命令危险规则集、能力清单、凭据模式、业务阈值）→ 调用方，
    本仓只定义**承载它的数据结构与判定链**。
- **机制与策略的分界举例**：`bashguard` 给 `Analyze(cmd, *Table) Decision`
  的裁决机制，**不给**「哪些命令危险」；`permgate` 给判定链与 deny 优先语义，
  **不给**具体 Capability 清单。把这些写成包内常量，就是把调用方资产焊进原语仓。
- **不得引入领域词**。本仓是 tier 0，地板被矩阵每一层继承——一层业务味会顺着
  依赖树扩散到全矩阵。
- **测试夹具用合成数据**。夹具是契约的示例，示例带领域味等于把契约钉死在某个领域上。

## 两处已知误用陷阱（改动相关代码时必须保留这些说明）

1. **`egress` 不解析 DNS**：`checkHost` 对域名直接放行。直接拿它挡 LLM 可控 URL
   会得到**零 DNS-rebinding 防护**。它提供的是「逐 IP 策略判定」原语，
   解析职责在调用方。
2. **`fence` 与 `injectband` 互补不可互相替代**：`fence` 封数据侧（不可信内容不得
   越出数据区取指令待遇），`injectband` 封系统侧（系统带外注入的身份标记不得被伪造）。
   删掉任一个都会开一个真实的注入面——改这两包时不要当作冗余清理。

## 与 oekit 家族的一致性

本仓**依赖** oekit（Open Easy Kit，Go 微服务工具链）的 `oekit/logx`。
两者是独立矩阵，不是子品牌。

- **错误处理统一走 `oekit/pkg/errors`**：哨兵用 `pkg/errors.New`，
  包装用 `pkg/errors.Wrap(err, msg, kv...)`（变参 kv，非 `Wrapf`；nil-safe +
  kv 结构化上下文），判定用同包 `Is`/`As`，解包到根用 `Cause`。
  **链路保持单 import**，不与 stdlib `errors` 或 `github.com/pkg/errors` 双混——
  混用会打断 `As`/`Is` 的类型判定（同型透传一旦断链，判定静默失效）。
- tier 0 加依赖等于给全矩阵抬地板：**新增依赖前先问「矩阵每一层都会被抬吗」**。

## 工程门禁

CI 是**薄调用层**：规则本体在 `oagentkit/.github` 的共享工作流，各仓 `ci.yml`
只传 `go-version`。**改门禁规则只改那一个仓，本仓不动。**

提交前本机验证：

```bash
gofmt -l .                 # 应无输出
go vet ./...
go test ./... -cover
```

- 新增包必须带测试，覆盖率不靠删用例达标。
- 本仓**没有** Makefile，不要凭空引用 `make check` 一类不存在的入口。

## 本机环境

- **一切 `go build` / `go test` 带 `CGO_ENABLED=0`**（macOS 新 SDK 27.0 与 CLT
  linker 不兼容 + Xcode 许可未接受）。
- 若遇模块缓存写入被沙箱拒绝（`rename`/`unlinkat ... operation not permitted`），
  那是环境限制不是代码问题——把 `GOMODCACHE` 指向工作区内再试，不要因此改 go.mod。

## 会话协作

- 提交用 `git add <具体路径>`，**禁止 `git add -A`**。
- 中文文档批量编辑后 `grep U+FFFD` 自检。
- macOS bash 3.2 多字节炸弹：`$VAR` 后紧跟中文/全角字符时 bash 会把多字节首字节
  吞进变量名，`set -u` 下直接崩——一律写 `${VAR}`。
