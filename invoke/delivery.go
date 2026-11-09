package invoke

// Delivery 说这次调用「发出去多远」——「跑没跑」之外的第三问（#134）。
//
// # 为什么需要第三问
//
// 动作层的词汇已齐两问：Allowed（门放没放）与 Acted（事做没做），
// WouldExecute 补了演练（若真跑会不会跑）。但「会重复执行 = 危险」的命令类
// 工具（shell / SSH / 任何把请求送到本进程之外的东西）还有第三问：
// **命令到底发出去没有**——
//
//   - DeliveryNotSent：请求根本没离开本进程 ⇒ 重试安全；
//   - DeliveryMaybeSent：可能已在远端跑 ⇒ **永不重放**；
//   - 空（未声明）：没有任何一层声明 ⇒ **不等于「没送到」**。
//
// 分不清「没投递」与「可能已投递」的后果，就是同一条 `rm -rf` 跑两遍：
// 事故模型不新——SSH 协议（RFC 4254）里服务器先回包再执行，写失败 =
// not_sent、回包丢失 = maybe_sent，这类判据每家执行类工具都该有一份，
// 而留痕是这个词汇唯一的传播通道。
//
// # 独立一列，互不推导
//
// 它与 Allowed / Acted 分属不同的事实面，**互不推导**：
//
//   - Allowed=false 不推导 DeliveryNotSent：链看得见「没到达执行体」，
//     看不见「执行体把请求发到了哪」，替它声明就是把两个事实面焊死；
//   - Acted / DryRun / Refused 也不推导它：演练什么都没跑，但「没发出去」
//     仍由执行体显式声明——「声明了」与「没人说」必须可区分，自动推导
//     恰好抹掉这个差别。
//
// 重试策略是调用方的事，本包不做；本包只负责把「说了的」如实带进留痕。
// 审计把它当**独立一列**（与 Allowed / Acted 并列），空值按「未声明」展示，
// 不得渲染成 not_sent——缺位 ≠ not_sent，这一句是这个词汇存在的全部理由。
type Delivery string

const (
	// DeliveryNotSent 请求根本没离开本进程 ⇒ 重试安全。
	DeliveryNotSent Delivery = "not_sent"
	// DeliveryMaybeSent 请求可能已在远端执行 ⇒ 永不重放。
	DeliveryMaybeSent Delivery = "maybe_sent"
)

// DeliveryOf 返回执行体声明的投递状态（nil 安全）。
//
// 返回值三格：
//
//   - DeliveryNotSent：请求没离开本进程，重试安全；
//   - DeliveryMaybeSent：可能已在远端执行，永不重放；
//   - 空：没人说——**不得读作「没送到」**。
//
// 链不推导这一列：门禁拦下（Allowed=false）与执行体未声明的留痕，
// 这一列同样是空。判定口径见 Delivery。
func (r Record) DeliveryOf() Delivery {
	if r.Outcome == nil {
		return ""
	}
	return r.Outcome.Delivery
}
