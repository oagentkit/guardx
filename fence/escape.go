package fence

import "strings"

// EscapeUntrusted 中和不可信文本（LLM 产出、用户输入）中的 markdown 结构与
// HTML 注释边界，防止攻击者借 diff/PR 描述注入伪造报告标题、列表条目等。
// 与 Data（数据区围栏）同属本包的注入卫生面：Data 圈住不可信内容的边界、
// EscapeUntrusted 中和不可信内容自身的 markdown 语义。
// 策略：HTML 注释开/闭序列实体化；行首标题/引用/代码围栏/列表标记/水平线/
// 表格行/引用定义前插零宽空格；反引号替换为同类引号防打断代码段。
// 前提：下游渲染器仍需自行 sanitize 裸 HTML（本包不处理 <img>/<script> 等标签）。
func EscapeUntrusted(s string) string {
	// 行终止符归一（第九轮审计：CommonMark 把 \r 视为行终止符——`好评\r# 标题`
	// 在渲染器侧是两行，按 \n 切分则是一行，行首判定被绕过即注入面）
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")

	if s == "" {
		return s
	}
	s = strings.ReplaceAll(s, "<!--", "&lt;!--")
	s = strings.ReplaceAll(s, "-->", "--&gt;")
	s = strings.ReplaceAll(s, "`", "′")
	var b strings.Builder
	b.Grow(len(s))
	for i, line := range strings.Split(s, "\n") {
		if i > 0 {
			b.WriteByte('\n')
		}
		trimmed := strings.TrimLeft(line, " \t")
		inject := false
		switch {
		case strings.HasPrefix(trimmed, "#"), strings.HasPrefix(trimmed, ">"), strings.HasPrefix(trimmed, "~~~"):
			inject = true
		case len(trimmed) >= 2 && strings.Trim(trimmed, "=-") == "":
			inject = true
		case len(trimmed) >= 3 && strings.Trim(trimmed, "*_- ") == "":
			// 水平线 *** / ___ / * * *（--- 已由上一条覆盖）
			inject = true
		case strings.HasPrefix(trimmed, "|"):
			// 表格行（| --- | 伪造"汇总表"是常见注入形态）
			inject = true
		case isPipeTableLine(trimmed):
			// GFM 表格行前导 | 可选（#67）：`name | score` 与分隔行
			// `--- | ---` 同样能立表格——尤其分隔行，没有它整张伪造表
			// 都不成立，必须中和。含 " | " 的普通行误伤代价只是行首一个
			// 零宽空格（渲染不变样），与放过伪造表格的代价不可比。
			inject = true
		case strings.HasPrefix(trimmed, "[") && strings.Contains(trimmed, "]:"):
			// 引用定义 [ref]: url，可劫持后文 [text][ref] 的渲染
			inject = true
		case strings.HasPrefix(trimmed, "- "), strings.HasPrefix(trimmed, "+ "), strings.HasPrefix(trimmed, "* "),
			// tab 紧随 bullet 符号（CommonMark 合法列表项——第九轮审计：有序
			// 分支已认 tab，bullet 三分支漏了同一语义）
			(len(trimmed) > 1 && (trimmed[0] == '-' || trimmed[0] == '+' || trimmed[0] == '*') && trimmed[1] == '\t'):
			inject = true
		case isOrderedMarker(trimmed):
			inject = true
		}
		if inject {
			b.WriteString("&#8203;")
		}
		b.WriteString(line)
	}
	return b.String()
}

// isPipeTableLine 无前导 | 的 GFM 表格行判定（#67）：
//   - 分隔行形态：只剩 | : - 空格（如 "--- | ---"、"---|---"、":-:|-:"）——
//     GFM 表格必须有分隔行才成立，把它中和掉，伪造的表就立不起来；
//   - 行内含 " | "（两侧带空格的管道，如 "name | score"）：GFM 的前导 |
//     与尾 | 都是可选的，这类行可作表头/表体。
//
// 无空格的 "a|b" 形态刻意不判：分隔行已被上一条覆盖（表格没有分隔行不成表），
// 而无空格竖线在正常文本（代码说明、正则）里出现频率高，误伤面大于安全收益。
func isPipeTableLine(trimmed string) bool {
	if !strings.Contains(trimmed, "|") {
		return false
	}
	if strings.Trim(trimmed, "|:-= ") == "" {
		return true // 分隔行形态（= 一并容纳，与水平线判定字符集对齐）
	}
	return strings.Contains(trimmed, " | ")
}

// isOrderedMarker 行首是否为有序列表标记（"12. xxx"）。
func isOrderedMarker(trimmed string) bool {
	i := 0
	for i < len(trimmed) && trimmed[i] >= '0' && trimmed[i] <= '9' {
		i++
	}
	return i > 0 && i+1 < len(trimmed) && (trimmed[i] == '.' || trimmed[i] == ')') &&
		(trimmed[i+1] == ' ' || trimmed[i+1] == '\t') // CommonMark 允许 tab 与 1) 形态（第九轮审计补）
}
