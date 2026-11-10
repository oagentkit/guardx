package invoke

import (
	"context"
	"testing"

	"github.com/oekit/pkg/errors"
)

// ── 第三问：投递状态轴（#134）──
//
// 动作层已有两问：Allowed（门放没放）与 Acted（事做没做），WouldExecute 补了
// 演练（若真跑会不会跑）。本组用例钉住第三问：**命令到底发出去没有**。
//
// 「会重复执行 = 危险」的命令类工具靠它区分两种结局：
//   - not_sent：请求根本没离开本进程 ⇒ 重试安全；
//   - maybe_sent：可能已在远端跑 ⇒ 永不重放。
//
// 分不清「没投递」与「可能已投递」的后果，就是同一条 rm -rf 跑两遍。

// TestDeliveryStringValues 钉住投递状态的字符串拼写。
//
// 审计按这一列的字符串值过滤（独立一列），拼写是事实上的线上契约：
// 改拼写 = 改掉下游所有过滤器的匹配键。
func TestDeliveryStringValues(t *testing.T) {
	if DeliveryNotSent != "not_sent" {
		t.Fatalf("DeliveryNotSent 拼写必须是 not_sent，实得 %q", string(DeliveryNotSent))
	}
	if DeliveryMaybeSent != "maybe_sent" {
		t.Fatalf("DeliveryMaybeSent 拼写必须是 maybe_sent，实得 %q", string(DeliveryMaybeSent))
	}
}

// TestDeliveryMaybeSentReachesRecordViaError 钉住本组用例的核心断言（验收样例）：
// 工具在 handler 里以 **error 返回**声明「可能已送出」，留痕必须记录该值。
//
// 这是投递状态轴存在的全部理由所在的那类结局：SSH 写成功但回包丢失——
// 执行失败，但命令可能已在机器上跑。留痕里若没有这一列，调用方分不清
// 「没投递」与「可能已投递」，重试就是同一条命令跑两遍。
//
// 反证样本：错误路径丢弃执行体声明（只抄成功路径），本用例立刻红。
func TestDeliveryMaybeSentReachesRecordViaError(t *testing.T) {
	_, rec := recordOf(t, func(context.Context, Call) (Result, error) {
		return Result{
				Text: "ssh 写入成功但回包丢失",
				Outcome: &Outcome{
					Delivery: DeliveryMaybeSent,
				},
			},
			errors.New("执行体回报失败：回包丢失")
	})

	if rec.Err == nil {
		t.Fatal("执行体报错 ⇒ 收口原因必须留痕")
	}
	if rec.Outcome == nil {
		t.Fatal("错误路径也必须保留执行体声明的结论")
	}
	if got := rec.DeliveryOf(); got != DeliveryMaybeSent {
		t.Fatalf("错误路径的投递声明必须原样进留痕，实得 %q", string(got))
	}
	// 门禁层不受影响：执行体确实被到达了。
	if !rec.Allowed {
		t.Fatal("投递声明不改变门禁层结论：调用确实到达了执行体")
	}
}

// TestDeliveryNotSentReachesRecord 钉住另一格：声明「没发出去」的留痕。
//
// not_sent 是唯一重试安全的一格——执行体在发出请求之前就失败了，
// 调用方读到它才敢退避重试。
func TestDeliveryNotSentReachesRecord(t *testing.T) {
	_, rec := recordOf(t, func(context.Context, Call) (Result, error) {
		return Result{
			Text:    "连接被拒，请求未发出",
			Outcome: &Outcome{Delivery: DeliveryNotSent},
		}, nil
	})

	if got := rec.DeliveryOf(); got != DeliveryNotSent {
		t.Fatalf("not_sent 声明必须原样进留痕，实得 %q", string(got))
	}
	if rec.Err != nil {
		t.Fatalf("成功收口 ⇒ 收口原因应为空，实得 %v", rec.Err)
	}
}

// TestDeliveryUndeclaredIsEmptyNotNotSent 钉住整个词汇的立身之本：
// **缺位 ≠ not_sent**。
//
// handler 未声明 ⇒ 留痕该列为空。空不得被读成「没送到」——没有任何一层
// 声明时，唯一安全的读法是「可能已送出」。把缺位实现成返回 DeliveryNotSent
// 的任何「兜底」，本用例立刻红。
func TestDeliveryUndeclaredIsEmptyNotNotSent(t *testing.T) {
	_, rec := recordOf(t, func(context.Context, Call) (Result, error) {
		return Result{Text: "真的执行了"}, nil
	})

	if got := rec.DeliveryOf(); got != "" {
		t.Fatalf("未声明 ⇒ 投递列必须为空，实得 %q", string(got))
	}
	if rec.DeliveryOf() == DeliveryNotSent {
		t.Fatal("缺位不得等于 not_sent——那是把「没人说」谎报成「没送到」")
	}
	if rec.DeliveryOf() == DeliveryMaybeSent {
		t.Fatal("缺位同样不得等于 maybe_sent——链不替执行体下结论")
	}
}

// TestDeliveryOfIsNilSafe 钉住留痕侧访问器的 nil 安全：
// 门禁拦下的留痕（Outcome 为 nil）读投递列不 panic，且同样为空。
//
// 注意空的方向：门禁拦下 ⇒ 请求确实没到达执行体，但链**不推导**
// DeliveryNotSent——链看得见「没到达执行体」，看不见「执行体把请求
// 发到了哪」，替它声明就是把两个事实面焊死。
func TestDeliveryOfIsNilSafe(t *testing.T) {
	var rec Record
	if got := rec.DeliveryOf(); got != "" {
		t.Fatalf("零值留痕的投递列必须为空，实得 %q", string(got))
	}
	if rec.DeliveryOf() == DeliveryNotSent {
		t.Fatal("零值留痕不得读出 not_sent")
	}

	// 门禁拦下：Allowed=false，投递列仍为空（不推导）。
	var denied Record
	c, _ := NewChain(okHandler(new(int)), []Stage{deny("gate", false)},
		WithRecorder(func(r Record) { denied = r }))
	_, _ = c.Do(context.Background(), Call{Name: "t"})
	if denied.Allowed {
		t.Fatal("门禁拦下 ⇒ Allowed 必须为 false")
	}
	if got := denied.DeliveryOf(); got != "" {
		t.Fatalf("门禁拦下 ⇒ 投递列必须为空（链不推导），实得 %q", string(got))
	}
}

// TestDeliveryAxisIndependentOfActed 钉住「互不推导」：投递状态轴与
// Allowed / Acted 是三个独立事实，任何一格的存在都不得改写另外两轴的结论。
//
// 反证样本：把 Delivery 并进 Acted 判定（比如 maybe_sent 就当「动了」或
// 「没动」），本用例立刻红。
func TestDeliveryAxisIndependentOfActed(t *testing.T) {
	// 只声明投递、不声明拒绝/演练 ⇒ 按既有语义仍是「做了」（声明了「做了」）。
	o := &Outcome{Delivery: DeliveryMaybeSent}
	if !o.Acted() {
		t.Fatal("投递声明不得改写 Acted：未拒未演练 ⇒ 仍是「做了」")
	}
	rec := Record{Allowed: true, Outcome: o}
	if !rec.Acted() {
		t.Fatal("留痕侧同理")
	}

	// 拒绝 + not_sent：拒绝是拒绝（Acted=false），投递是投递（not_sent），
	// 两格并存互不覆盖。
	o2 := &Outcome{Refused: "缺 confirm", Delivery: DeliveryNotSent}
	if o2.Acted() {
		t.Fatal("拒绝 ⇒ Acted 为 false，不因投递声明而变")
	}
	rec2 := Record{Allowed: true, Outcome: o2}
	if rec2.DeliveryOf() != DeliveryNotSent {
		t.Fatalf("拒绝路径的投递声明必须保留，实得 %q", string(rec2.DeliveryOf()))
	}

	// 演练 + not_sent：演练什么都没跑，执行体显式声明 not_sent 是如实留痕，
	// 但两格仍然独立——链不得替演练自动推导 not_sent（那会掩盖「声明了」
	// 与「没人说」的差别）。
	o3 := &Outcome{DryRun: true, Delivery: DeliveryNotSent}
	if o3.Acted() {
		t.Fatal("演练 ⇒ Acted 为 false，不因投递声明而变")
	}
	rec3 := Record{Allowed: true, Outcome: o3}
	if !rec3.DryRun() {
		t.Fatal("演练标记必须与投递声明同时在位")
	}
	if rec3.DeliveryOf() != DeliveryNotSent {
		t.Fatalf("演练路径的投递声明必须保留，实得 %q", string(rec3.DeliveryOf()))
	}
}
