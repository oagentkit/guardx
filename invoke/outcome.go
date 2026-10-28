package invoke

// Outcome 动作层结论——执行体自己的说法：「事情做没做」。
//
// # 为什么需要它
//
// 一次调用有**两层**结论，分属两层事实：
//
//   - **门禁层**（Record.Allowed / Record.Err）：门禁判了什么。门禁能看见的只有
//     capability 与 confirm 标志，**命令是什么只有工具知道**。
//   - **动作层**（本类型）：事情做没做。只能由执行体给出。
//
// 只留门禁层会漏掉一整类结局：工具在执行体内部自己拒绝了这次动作（缺 confirm）、
// 或做了一次演练（什么都没跑，但这是调用方要的），两者都以**一次成功返回**结束
// ⇒ 门禁层长成 Allowed=true, Err=nil，而 Allowed 读起来是「执行了」。
//
// # 两个字段必须独立
//
// 「拒绝」与「演练」不可合成一个 bool：合成之后下游一定会把演练记成拒绝——
// 那是在审计唯一要回答的那个问题上造假警报。演练不是拒绝，是调用方要的行为。
type Outcome struct {
	// Refused 非空 ⇒ 执行体拒绝执行本次动作；值是拒绝原因。
	//
	// 用字符串而非 bool：拒绝原因本身就是审计要留的东西（缺 confirm？
	// 超出配额？），把它压成一个 bool 就等于把原因扔在门外。
	Refused string
	// DryRun 为真 ⇒ 本次是演练：什么都没跑，但这是调用方要的（不是拒绝）。
	DryRun bool
}

// Acted 报告「事情做没做」。
//
// 判定表：
//
//   - o == nil            ⇒ true。未声明按「执行了」处理，保持既有调用方行为不变。
//   - Refused 非空        ⇒ false。执行体自己拒了，什么都没做。
//   - DryRun 为真         ⇒ false。演练：什么都没跑。
//   - 其余                 ⇒ true。执行体声明了「做了」。
//
// nil 安全：调用方拿到 *Outcome 之后不必先判空——未声明与「声明了但做了」
// 在这里都是 true，判空只会在下游写出一份漏判的分支。
func (o *Outcome) Acted() bool {
	if o == nil {
		return true
	}
	return o.Refused == "" && !o.DryRun
}

// RefusalReason 返回执行体给出的拒绝原因；未声明或未拒绝时返回空串。
//
// nil 安全：调用方不必先判空就能读到「为什么被拒」——审计要的正是这句话。
func (o *Outcome) RefusalReason() string {
	if o == nil {
		return ""
	}
	return o.Refused
}
