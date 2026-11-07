// Package injectband 系统带外注入提示的**防伪包裹通道**。
//
// # 与 fence 的分工
//
// 两者互补而非替代，各自封一个方向：
//
//   - fence（数据侧）：把不可信内容圈进数据区，防其伪造边界标记越权取指令待遇；
//   - injectband（系统侧）：给系统写入的带外提示打上来源标记，并保证该标记
//     自身不可被内容伪造——否则不可信文本可以伪造「这是系统说的」来抬升权限。
//
// 只有 fence 时，系统提示与用户文本在模型眼里仍是同一等公民：攻击者不必逃出
// 数据区，只需在里面写一个像系统注入的标签即可。本包补的就是这个缺口。
//
// # 三件套
//
//  1. source 元数据声明来源，模型可区分系统注入与用户输入；
//  2. body 内伪造的标签（含大小写/空白变体）统一转义，杜绝嵌套包裹越权；
//  3. 只用于 LLM 面（prompt 组装），用户可见面（时间线、报告渲染）保持原文不带标签。
//
// # 纪律
//
// 包裹体的 body 来自用户输入 / 工具产出 / 历史结论等**不可信内容**时，
// 必须经本包转义后再进 prompt——外部 webhook 文本、命令输出、
// 抓取的网页正文都是提示注入的现实入口。
//
// 本包零依赖，与任何宿主领域无关：它是 LLM 应用的通用提示注入面。
package injectband

import (
	"regexp"
	"strings"
)

// tagRe 匹配待转义的伪造标签：容许大小写与 `<` 后的空白变体。
var tagRe = regexp.MustCompile(`(?i)<\s*/?\s*system-reminder`)

// SanitizeBody 转义 body 内伪造的系统注入标签（`<` → `&lt;`，保留其余原文）。
// 包裹前调用；包裹函数自身不会再产出可被二次解析的嵌套结构。
func SanitizeBody(body string) string {
	return tagRe.ReplaceAllStringFunc(body, func(m string) string {
		return strings.Replace(m, "<", "&lt;", 1)
	})
}

// sourceEscaper source 属性值的实体转义（#68）：source 进的是双引号属性值，
// `"` 闭合属性、`<` 伪造标签、`>` 提前闭合开标签——其后文本都会变成顶层
// prompt 内容。& 必须最先替换，否则后续产出的实体会被二次转义。
// 用 strings.NewReplacer 单遍完成（先列先匹配，天然避免二次转义）。
var sourceEscaper = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	`"`, "&quot;",
	"'", "&apos;",
)

// Wrap 以统一通道包裹系统带外注入：`<system-reminder source="…">…</system-reminder>`。
//
// source 若来自配置面（工具名/MCP server 名）而非编译期常量，同样是不可信
// 输入——它被做属性级实体转义后才进 source="…"，杜绝属性逃逸。
func Wrap(source, body string) string {
	var b strings.Builder
	b.WriteString(`<system-reminder source="`)
	b.WriteString(sourceEscaper.Replace(source))
	b.WriteString(`">` + "\n")
	b.WriteString(SanitizeBody(strings.TrimSpace(body)))
	b.WriteString("\n</system-reminder>")
	return b.String()
}
