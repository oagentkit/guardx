# guardx

安全围栏 —— oagentkit 模块矩阵 **tier 0**（基础层）。

```
go get github.com/oagentkit/guardx
```

| 包 | 职责 |
|---|---|
| `fence` | 中和不可信文本（LLM 产出、用户输入）中的 markdown 结构，防提示词注入 |
| `logredact` | 日志/审计载荷凭据脱敏：连接串/URL/头中的凭据在落日志前模式化打码 |
| `egress` | 出口围栏：LLM 可控 URL 的字面量层 SSRF 防护 |
| `permgate` | 工具调用许可判定链：谁在什么模式下对什么输入得到什么许可 |
| `bashguard` | bash 命令静态风险解析：不执行命令，经真 shell AST 判定 |
| `audit` | 审计日志：对敏感操作留结构化审计痕迹，与业务日志分离 |

## 定位

**tier 0，矩阵的安全基座。** 所有需要「对外输出不可信内容」或「执行外部命令」的场景都应
先过本仓的对应包。

`audit` 的日志门面用的是 `github.com/oekit/logx` 的 `NewAuditLogger` —— 门面级承诺
级别锁 `Info`、不受 `LOG_LEVEL` 降级，避免审计痕迹被日志级别配置吞掉。

## 开发

```bash
go test ./... -race
go vet ./...
gofmt -l .
```

规范见 [AGENTS.md](AGENTS.md)。

## License

MIT
