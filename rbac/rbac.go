package rbac

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

// Matrix 角色→能力集矩阵（guardx#175）：宿主注入的声明面数据。键与值都是
// 宿主领域词汇（角色名、能力词），本包不预设、不归一（大小写敏感、原样
// 比对——词表的拼写纪律归宿主的词表闭合 lint 管）。
//
// 同一角色能力集内的重复词无语义（Can 是存在性判定，Snapshot 会去重）；
// 但建议宿主保持声明面整洁——矩阵是要被审计与指纹化的。
type Matrix map[string][]string

// Can 查表：role 的能力集是否含 perm。
//
// fail-closed：矩阵 nil、角色未声明、能力词未授予，一律 false——矩阵外
// 没有能力（包文档「fail-closed 缺省」）。不存在「默认角色」或前缀匹配：
// 能力词是封闭词表，词表外的字面量查不到就是查不到。
func (m Matrix) Can(role, perm string) bool {
	return slices.Contains(m[role], perm)
}

// ReadOnly 报告 role 是否只读档：**由矩阵推导**（guardx#175 的踩坑纪律）——
// 能力集内不含任何写面能力即只读，不硬编码 `role == "viewer"`（矩阵演进时
// 硬编码静默失真，见包文档）。
//
// writeFace 写面能力词集合（改动状态/施加副作用的能力词）。判据方向刻意
// 声明**写面**而不是读面：nil/空集合 ⇒ 无法证明任何能力是读面 ⇒ 一律推导
// 为只读（写面全禁）——漏声明得到的是「全禁」，不是「全放」（fail-closed，
// 与 Can 的矩阵外无能力同一方向）。不在矩阵里的角色能力集为空 ⇒ 只读档。
//
// 推导结果的使用方（宿主把只读角色钉进只读档/写面全禁）即便误判也仍有
// Can 这层兜底：ReadOnly=false 的角色对未授予的写能力词照样 Can=false。
// 本判定是 belt，矩阵是 suspenders——两层都取保守侧。
func (m Matrix) ReadOnly(role string, writeFace map[string]bool) bool {
	for _, perm := range m[role] {
		if writeFace[perm] {
			return false
		}
	}
	return true
}

// Snapshot 授权面指纹：矩阵的**确定性**序列化——角色按字典序，每行
// "role=perm1,perm2"（行内能力词去重 + 字典序，逗号连接，LF 换行）。
//
// 用途（#175 (b)：policyver 类消费）：对本串做哈希即得授权面指纹——矩阵
// 声明的任何增删改都会改变指纹，授权面漂移因此可被指纹比对捕获。序列化
// 是规范的（同矩阵恒同串），不是实现细节；跨版本依赖它请钉住本方法文档。
//
// nil/空矩阵返回空串（指纹意义上的「空授权面」）。
func (m Matrix) Snapshot() string {
	var b strings.Builder
	for _, role := range slices.Sorted(maps.Keys(m)) {
		perms := slices.Clone(m[role])
		slices.Sort(perms)
		perms = slices.Compact(perms)
		fmt.Fprintf(&b, "%s=%s\n", role, strings.Join(perms, ","))
	}
	return b.String()
}

// FindingKind lint 疑点类型。
type FindingKind string

const (
	// FindingUnconsumedPerm 能力词在矩阵中声明，但宿主报告执行面无消费点
	// （或消费点回调未注入——无法核实视同无消费点，fail-loud：lint 不静默
	// 放过任何一条能力词，「矩阵不得装饰化」判据的死法就是沉默）。
	FindingUnconsumedPerm FindingKind = "perm.unconsumed"
	// FindingUnknownRole 矩阵角色不在宿主声明的角色词表内（词表闭合破坏）
	// ——十有八九是拼写错造出的新角色：它查得到、授权面却分叉了。
	FindingUnknownRole FindingKind = "role.unknown"
	// FindingNonMonotonic 角色层级单调性破坏：高层角色的能力集缺低层角色的
	// 能力（矩阵单调：高层 ⊇ 低层）。单调破坏的典型成因是往低层加了新能力
	// 词而忘了同步高层——高层身份反而比低层少权限。
	FindingNonMonotonic FindingKind = "matrix.nonmonotonic"
)

// Finding 一次 lint 的疑点报告。Role/Perm 视疑点类型可空：
// FindingUnconsumedPerm 填 Perm（Role 为首个授予它的角色，作定位线索）、
// FindingUnknownRole 填 Role、FindingNonMonotonic 填 Role（高层）+ Perm。
type Finding struct {
	Kind   FindingKind
	Role   string
	Perm   string
	Detail string
}

// LintOptions lint 骨架的宿主注入面（guardx#175：判据是机制的，事实是
// 宿主的——消费点在哪、角色词表长什么样，本包无从知晓）。
type LintOptions struct {
	// ConsumedBy 能力词消费点回调：宿主报告 perm 在执行面是否有真实消费点
	// （requirePerm/Can 调用点注册表、handler 门禁清单……由宿主自持）。
	// nil ⇒ 无法核实 ⇒ **每条**能力词报 FindingUnconsumedPerm（fail-loud，
	// 见该常量注释）。回调可能被逐词调用多次，应轻量；判定口径由宿主定
	// （「至少一处消费点」是推荐语义）。
	ConsumedBy func(perm string) bool
	// Roles 声明面的角色词表全集：矩阵中出现的角色必须都在其中（词表闭合）。
	// len==0 视为未提供，闭合判据跳过（宿主没有角色词表时不要硬凑空表）。
	Roles []string
	// Order 角色层级，从高到低（如 admin, user, viewer）：单调性判据用——
	// 相邻两层做包含核对（高层 ⊇ 低层），由传递性覆盖全链。len==0 视为
	// 未提供，单调判据跳过（无层级语义的扁平角色表不需要它）。层级里声明
	// 而矩阵未列的角色按空能力集参与核对（高层缺位即缺能力）。
	Order []string
}

// Lint 「矩阵不得装饰化」lint 骨架（guardx#175）：对声明面跑三条判据，
// 逐条产出 Finding（不 panic、不修改矩阵；返回 nil = 所提供的判据全过）。
//
// 输出顺序确定（按角色/能力词字典序），供快照比对与 CI 断言；宿主接自己的
// 告警/门禁面（测试里 t.Fatal、启动时日志、CI 里指纹比对皆可）。三条判据
// 相互独立：没提供的输入跳过对应判据（文档见 LintOptions 字段）——但
// ConsumedBy 未提供不会跳过，而是逐词报疑点：装饰化判据的失败模式必须是
// 响亮，不能是安静。
func (m Matrix) Lint(opts LintOptions) []Finding {
	var findings []Finding

	// 判据一：每条能力词必须有执行面消费点（矩阵不得装饰化）。
	permRole := map[string]string{} // perm → 首个授予它的角色（定位线索）
	for _, role := range slices.Sorted(maps.Keys(m)) {
		for _, perm := range m[role] {
			if _, ok := permRole[perm]; !ok {
				permRole[perm] = role
			}
		}
	}
	for _, perm := range slices.Sorted(maps.Keys(permRole)) {
		if opts.ConsumedBy != nil && opts.ConsumedBy(perm) {
			continue
		}
		findings = append(findings, Finding{
			Kind: FindingUnconsumedPerm,
			Perm: perm,
			Role: permRole[perm],
			Detail: fmt.Sprintf(
				"能力词 %q（如角色 %s 所列）在执行面无可核实消费点——矩阵不得装饰化：要么补上 requirePerm/Can 消费点，要么从矩阵删词",
				perm, permRole[perm]),
		})
	}

	// 判据二：角色词表闭合——矩阵里的角色必须在宿主词表内。
	if len(opts.Roles) > 0 {
		for _, role := range slices.Sorted(maps.Keys(m)) {
			if slices.Contains(opts.Roles, role) {
				continue
			}
			findings = append(findings, Finding{
				Kind:   FindingUnknownRole,
				Role:   role,
				Detail: fmt.Sprintf("矩阵角色 %q 不在声明面角色词表内（词表闭合破坏——多为拼写错造出的新角色）", role),
			})
		}
	}

	// 判据三：矩阵单调——相邻两层（高层 ⊇ 低层），传递性覆盖全链。
	if len(opts.Order) > 0 {
		for i := 0; i+1 < len(opts.Order); i++ {
			high, low := opts.Order[i], opts.Order[i+1]
			granted := map[string]bool{}
			for _, perm := range m[high] {
				granted[perm] = true
			}
			lowPerms := slices.Clone(m[low])
			slices.Sort(lowPerms)
			for _, perm := range lowPerms {
				if granted[perm] {
					continue
				}
				findings = append(findings, Finding{
					Kind: FindingNonMonotonic,
					Role: high,
					Perm: perm,
					Detail: fmt.Sprintf(
						"高层角色 %q 缺少低层角色 %q 的能力词 %q（矩阵单调：高层 ⊇ 低层）",
						high, low, perm),
				})
			}
		}
	}

	return findings
}
