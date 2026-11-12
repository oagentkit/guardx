// Package permgate 工具调用许可判定链：谁在什么模式下对什么输入得到
// allow/ask/deny。对标 ZCode permission/service.ts 的优先级状态机——顺序是
// 踩坑固化的，别调换：
//
//	requiresUserInteraction → ask（交互型工具天然要用户）
//	alwaysAsk 硬阻断段 → disallowed/project-deny 仍压过「问」（被硬禁的
//	  工具不能退化成「弹窗一点就能跑」）
//	alwaysAsk 会话授权段 → 命中即放行（钥匙是本会话的授权，不看模式）
//	alwaysAsk 只读拦截段 → 只读档的非只读工具直接拒（不给「问」的机会）
//	disallowed → deny
//	project deny → deny
//	配置白名单 → allow（break-glass 位次，issue #58：运维显式加白是「比模式
//	  更强的信任」，压过只读档与 project ask；硬禁仍在它前面——白名单不是
//	  绕禁的后门）
//	只读拦截 → deny（只读档的非只读工具直接拒——「禁」压过「问」）
//	yolo → 放行（alwaysAsk 与一切「禁」都在它前面——yolo 跳过的是「问」不是「禁」）
//	project ask → ask
//	只读模式 → 只读工具放行、其余拦下
//	project allow → allow
//	预批钩子 → allow（WebFetch URL 白名单类）
//	兜底 → 会话授权、只读工具放行，其余 ask
//
// 「只读拦截」段是「只读模式」段的前置影子：只读档对非只读工具是「禁」不是
// 「问」——它必须压过 alwaysAsk 与 project ask 两处「问」，否则只读退化成
// 「换个姿势问」（issue #24）。它与后段同 RuleID/Reason，审计口径不变；
// mode 之间互斥，故它与 yolo 段无交集。唯一的例外是配置白名单（#58 的
// break-glass）：只读档默认禁写，但运维对单个工具的显式加白压得过模式档
// （下游不再需要在 permgate 之外私设一层本地 override，授权真相只有一份）。
//
// 与 agentkit policy（操作审计门：四模式裁决矩阵）正交：policy 裁「业务操作
// 该不该做」，permgate 裁「这次工具调用要不要人确认」。
//
// 规则内容匹配（对标 matchesRuleContent）：精确 / `prefix:*` 前缀（prefix 或
// prefix+空白开头——空白含换行，换行同属命令分隔）/ `*` 通配（跨行透明）。
// 匹配对象从工具输入提取（字段名按 Service.SubjectKeys 清单，缺省
// command/url/file_path/path/pattern/patch_text，或字符串输入本身）；类型化
// 输入（map[string]string、struct 及其字段/json tag）同样参与提取（#65/#72：
// 此前这些形态静默落空，内容级 deny 对类型化调用方全部失配——fail-open）。
//
// ⚠️ subject 键清单是 ZCode 的领域词汇惯例（#86）：上述 6 键只是缺省值，不是
// 普遍契约。工具输入 schema 用其他字段名（cmd/script/target …）的宿主**必须**
// 配置 Service.SubjectKeys 声明自己的匹配对象字段——清单外字段是匹配盲区，
// 内容级 deny 规则对它们静默失效（规则还在配置里、审计显示「未命中 deny」，
// 实为死字且零报错，是 deny 规则最坏的失效形态）。为此 deny 档的失配另有
// fail-loud 出口：输入是 map/struct 形态却提取不出任何 subject 面时，经
// Service.OnConfigWarn 回调显式暴露（allow/ask 失配落 ask 兜底本就保守，
// 不告警）。工具名等价（Edit 规则匹配 Write 的写面特例）同样外置：
// Service.ToolEquivalence 钩子，nil = DefaultToolEquivalence（即原特例）。
//
// 复合命令（#62/#71/#129）：command 形态的匹配对象先按 shell 操作符（`&`
// 含 `&&`、`||` `;` `|` 换行，引号内不拆）拆段，段级命中的量词按规则极性取
// fail-closed 侧
// ——allow/会话授权要求**每段**都命中（`git status && curl evil` 不得搭
// `git status:*` 的车），deny/ask 只要**任一段**命中（复合命令里混进一段
// 危险命令即拦）。不追求完整 shell 语法：真 AST 形态（引号嵌套、算术展开等）
// 归 tools/bashguard，本包只做 stdlib 操作符切分，拆不动的形态宁可让 allow
// 失配（落 ask），不得让操作符后的命令搭车放行。
// 命令替换（#144）：段内含未引用化的 `$(`、反引号、`${` 时该段 allow 恒失配
// （单引号内为字面；双引号内照样执行/展开，不豁免）——替换体的真实命令
// 运行期才展开，字面前缀核对不了它，宁可落 ask（hasCommandSubstitution）。
// 重定向（#161）：段内含未加引号包裹的 `>` `<`（覆盖 `>>` `2>` `2>&1` `<<` 等）
// 时该段 allow 恒失配——重定向目标路径不在任何规则的审视面内，
// `git status > /etc/passwd` 不得搭 `git status:*` 的车放行；与替换体守门
// 语义有一处不同：单、双引号内都是字面（双引号内的 `>` 不构成重定向，
// `git status "a>b"` 不得误伤），反斜杠转义 `\>` 亦为字面（hasRedirect）。
package permgate

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/oekit/pkg/cache"
)

// Behavior 判定行为。
type Behavior string

const (
	Allow Behavior = "allow"
	Ask   Behavior = "ask"
	Deny  Behavior = "deny"
)

// Mode 会话模式。
type Mode string

const (
	// ModeDefault 正常模式（兜底：只读放行、其余问）。
	ModeDefault Mode = "default"
	// ModeYolo 直通模式（跳过确认——但压不过 alwaysAsk 与硬禁）。
	ModeYolo Mode = "yolo"
	// ModeReadOnly 只读模式（plan 类：只放行只读工具）。
	ModeReadOnly Mode = "read_only"
)

// Capability 工具能力自报（注册期声明）。
type Capability struct {
	// ReadOnly 只读工具（读后无副作用）。
	ReadOnly bool
	// AlwaysAsk 工具自报必须逐次确认（不可被模式/白名单绕过，只可被硬阻断
	// 与会话授权短路）。
	AlwaysAsk bool
	// RequiresUserInteraction 用户交互型工具（AskUserQuestion 类）。
	RequiresUserInteraction bool
}

// Rule 单条许可规则。
type Rule struct {
	// ToolName 工具名；等价工具名按 Service.ToolEquivalence 判定（nil =
	// DefaultToolEquivalence：Edit 规则匹配 Write 的写面等价，ZCode 特例）。
	ToolName string
	// Content 输入内容模式（command/url/路径）：空 = 该工具全部调用；
	// "git status:*" 前缀（空白边界，命令形态专用）；含 * 通配；否则精确等值。
	// ⚠ 路径规则用 wildcard 形态（"/repo/data/*"）而非前缀形态——前缀边界是
	// 空白/制表符，对路径子树形同虚设；路径 subject 匹配前会 filepath.Clean
	//（`..` 穿越不命中），符号链接围栏归执行器——单源见 sandbox.FSFence
	//（文本严格档 + EvalSymlinks 落地 + cwd 语义，guardx#117）。
	Content string
}

// Ruleset 三档规则集。
type Ruleset struct {
	Allow []Rule
	Ask   []Rule
	Deny  []Rule
}

// Decision 判定结果（RuleID 结构化审计）。
type Decision struct {
	Behavior Behavior
	RuleID   string
	Reason   string
}

// Service 许可判定器。零值可用（全部走兜底档）。
//
// 并发契约（issue #66）：Check/AllowForSession/ResetSession/Update/SessionAllows
// 之间并发安全——Check 全程只读锁内快照，Update 在锁内整体换配置。导出的
// 配置字段（AllowedTools/DisallowedTools/ProjectRules/Preapprove/SubjectKeys/
// ToolEquivalence/OnConfigWarn）视为**装配期字段**：直接赋值只允许发生在并发
// 使用开始前；运行期热更新一律经 Update 换**新值**（不得原地改切片元素——
// 快照共享底层数组，原地改与并发读仍构成竞争），也不得在 Update 回调里再调
// 本包方法（非重入锁，会死锁）。
type Service struct {
	// AllowedTools 配置级白名单（工具名集合）。break-glass 位次（#58）：
	// 运维显式加白压过只读档与 project ask，但压不过 disallowed/project deny。
	AllowedTools map[string]bool
	// DisallowedTools 配置级黑名单（压过 yolo、alwaysAsk 的确认段与白名单）。
	DisallowedTools map[string]bool
	// ProjectRules 项目/产品级规则集。
	ProjectRules Ruleset
	// Preapprove 预批钩子（WebFetch URL 白名单类）：返回非空 ruleID 即放行。
	// 判定位次在项目 allow 之后、配置白名单之后（plan 拦截压得过预批）。
	Preapprove func(ctx context.Context, tool string, input any) (ruleID string, ok bool)
	// SubjectKeys 工具输入里参与内容匹配的字段名清单（#86）。零值/空 = 内置
	// 6 键 command/url/file_path/path/pattern/patch_text（ZCode 领域词汇惯例，
	// 向后兼容）。⚠️ 工具输入 schema 用其他字段名（cmd/script/target …）的
	// 宿主**必须**配置本清单：清单外字段是匹配盲区，内容级规则对它们静默
	// 失配；deny 规则的这类失配经 OnConfigWarn fail-loud。清单按声明顺序
	// 提取；形态特判跟随键名本身——名为 command 的键仍按复合命令拆段、
	// file_path/path 仍先 filepath.Clean，清单里的自定义键按单段原样匹配
	// （命令形态的字段建议沿用内置名 command，或由宿主拆段后匹配）。
	SubjectKeys []string
	// ToolEquivalence 工具名等价钩子（#86）：a 为规则声明的工具名、b 为实际
	// 调用的工具名，等价（规则应覆盖该调用）返回 true——精确相等无需钩子。
	// nil = DefaultToolEquivalence（Edit 规则匹配 Write 的写面等价，ZCode
	// 特例降级为缺省实现）。宿主工具命名不同（EditFile/ApplyPatch …）时
	// 声明自己的写面等价，不必为每个变体名重复配规则。钩子是**替换**不是
	// 叠加：配置后 ZCode 特例不再自动生效，需要就写进自己的实现里。
	ToolEquivalence func(a, b string) bool
	// OnConfigWarn 配置疑点告警回调（#86 fail-loud）：本包无日志依赖，宿主
	// 经它接自己的日志/计数面。当前唯一告警点——deny 内容规则在「输入是
	// map/struct 形态但提取不出清单内任何 subject 字段」的调用上无法评估：
	// 该规则对此调用形同虚设，而后续档位可能放行。默认 no-op（零值可用）。
	// 回调在 Check 路径上同步触发且可能并发，必须轻量并自行保证并发安全；
	// 告警频度（同一规则反复触发）由宿主去重。allow/ask 失配落 ask 兜底
	// 本就保守，不告警。
	OnConfigWarn func(msg string)

	mu           sync.Mutex
	sessionRules Ruleset
}

// config Check 全程持有的配置快照（#66）：锁内取，锁外只读——热更新经 Update
// 整体换值后，进行中的判定仍基于取快照时刻的一致视图。subjectKeys/equiv/warn
// 是三个可配置面（#86）的**解析结果**：零值已在 snapshot 落到缺省实现
// （defaultSubjectKeys / DefaultToolEquivalence / no-op），判定路径上不再做
// 零值分叉。
type config struct {
	allowed     map[string]bool
	disallowed  map[string]bool
	project     Ruleset
	preapprove  func(context.Context, string, any) (string, bool)
	subjectKeys []string
	equiv       func(a, b string) bool
	warn        func(msg string)
}

// snapshot 锁内拷贝配置（map 引用 + 三个 slice 头，浅拷贝即可——Update 语义
// 要求换新值而非原地改）。#86 的三个可配置面在这里一并解析零值。
func (s *Service) snapshot() config {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := s.SubjectKeys
	if len(keys) == 0 {
		keys = defaultSubjectKeys
	}
	equiv := s.ToolEquivalence
	if equiv == nil {
		equiv = DefaultToolEquivalence
	}
	return config{
		allowed:     s.AllowedTools,
		disallowed:  s.DisallowedTools,
		project:     s.ProjectRules,
		preapprove:  s.Preapprove,
		subjectKeys: keys,
		equiv:       equiv,
		warn:        s.OnConfigWarn,
	}
}

// Update 运行期配置热更新（#66）：fn 在锁内拿到 Service 本体，对配置字段
// **整体赋新值**；与并发 Check 安全交错（Check 持锁内快照）。约束见类型注释。
func (s *Service) Update(fn func(*Service)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s)
}

// Check 判定一次工具调用。input 为工具入参（string、map[string]any、
// map[string]string 或 struct 等类型化形态——内容字段按 subjectKeys 名单提取）。
// 分段优先级见包注释——顺序是踩坑固化的，别调换。
func (s *Service) Check(ctx context.Context, tool string, input any, mode Mode, cap Capability) Decision {
	cfg := s.snapshot()
	switch {
	case cap.RequiresUserInteraction:
		return s.checkUserInteraction(cfg, tool, input)
	case cap.AlwaysAsk:
		return s.checkAlwaysAsk(cfg, tool, input, mode, cap)
	default:
		return s.checkStandard(ctx, cfg, tool, input, mode, cap)
	}
}

// decision 构造判定结果（RuleID 结构化审计）。
func decision(b Behavior, ruleID, reason string) Decision {
	return Decision{Behavior: b, RuleID: ruleID, Reason: reason}
}

// checkUserInteraction 交互型工具：硬禁与项目 deny 压过交互段——被 deny 的
// 交互型工具不该退化成「弹窗一点就能跑」（与 alwaysAsk 段同纪律）。
func (s *Service) checkUserInteraction(cfg config, tool string, input any) Decision {
	if d, hit := hardDeny(cfg, tool, input); hit {
		return d
	}
	return decision(Ask, "tool.userInteraction", "交互型工具需要用户参与: "+tool)
}

// checkAlwaysAsk 逐次确认工具：先走硬阻断，再看会话授权，最后问——
// 不可被模式/白名单放行。
//
// 只读拦截插在会话授权之后、ask 之前：只读档对非只读工具是「禁」不是「问」
// ——否则只读退化成「换个姿势问」（issue #24）。会话授权不在其列：那是用户
// 已经给出的决定（放行），不是一次「问」——保持「不看模式」的既有语义。
// 配置白名单同样不在此段放行（Capability 注释：AlwaysAsk 不可被白名单绕过）。
func (s *Service) checkAlwaysAsk(cfg config, tool string, input any, mode Mode, cap Capability) Decision {
	if d, hit := hardDeny(cfg, tool, input); hit {
		return d
	}
	if matchRules(s.sessionRuleSet().Allow, Allow, tool, input, cfg) {
		return decision(Allow, "rule.session.allow", "本会话已授权: "+tool)
	}
	if readonlyWrite(mode, cap) {
		return readonlyDeny(tool)
	}
	return decision(Ask, "tool.alwaysAsk", "工具要求逐次确认: "+tool)
}

// readonlyWrite 只读档里的非只读工具（写入类）——只读模式对它是「禁」。
//
// 判据与 checkStandard 的只读段同源：只有 cap.ReadOnly 的工具在只读档放行。
// mode 之间互斥，故本判据与 yolo 段永不同真。唯一例外是配置白名单
// （checkStandard 的 break-glass 位次，#58）——本段不含白名单短路：
// AlwaysAsk 工具本就不可被白名单绕过。
func readonlyWrite(mode Mode, cap Capability) bool {
	return mode == ModeReadOnly && !cap.ReadOnly
}

// readonlyDeny 只读拦截的裁决（单源）：与 checkStandard 只读段的 Deny 分支
// 同 RuleID/Reason——审计口径不因拦截位次而变。
func readonlyDeny(tool string) Decision {
	return decision(Deny, "mode.read_only", "只读模式拦下写入: "+tool)
}

// hardDeny 硬阻断单源（checkUserInteraction/checkAlwaysAsk/checkStandard 三段
// 此前逐字重复）：显式禁用工具与项目 deny 规则压过一切（含配置白名单的
// break-glass 位次——白名单不是绕禁的后门）——交互型/逐次确认类工具被 deny
// 时是 Deny 而非退化为「一点就能跑」的 ask（v0.10.30 审计语义，收口轮单源化）。
func hardDeny(cfg config, tool string, input any) (Decision, bool) {
	if cfg.disallowed[tool] {
		return decision(Deny, "rule.disallowedTools", "工具被显式禁用: "+tool), true
	}
	if matchRules(cfg.project.Deny, Deny, tool, input, cfg) {
		return decision(Deny, "rule.project.deny", "项目规则拒绝: "+tool), true
	}
	return Decision{}, false
}

// checkStandard 常规判定主干：与 ZCode 的历史差异——一切「禁」压过 yolo
// （其源码注释自述 yolo 先于硬禁是兼容遗留——新装配没有这个包袱）。
// yolo 跳过的是「问」，不是「禁」。
func (s *Service) checkStandard(ctx context.Context, cfg config, tool string, input any, mode Mode, cap Capability) Decision {
	switch {
	case cfg.disallowed[tool]:
		return decision(Deny, "rule.disallowedTools", "工具被显式禁用: "+tool)
	case matchRules(cfg.project.Deny, Deny, tool, input, cfg):
		return decision(Deny, "rule.project.deny", "项目规则拒绝: "+tool)
	case cfg.allowed[tool]:
		// 配置白名单 break-glass（#58）：运维显式加白是「比模式更强的信任」
		// ——压过只读档与 project ask（只读巡检/演示下仍放行单个显式信任的
		// 写工具）。硬禁（disallowed/project deny）在它前面。RuleID 标
		// rule.allowedTools 而非模式放行，审计可辨。
		return decision(Allow, "rule.allowedTools", "白名单放行: "+tool)
	case readonlyWrite(mode, cap):
		// 只读拦截：只读档对非只读工具是「禁」不是「问」——必须压过
		// project ask，否则只读退化成「换个姿势问」（issue #24）。
		return readonlyDeny(tool)
	case mode == ModeYolo:
		return decision(Allow, "mode.yolo", "yolo 模式直通")
	case matchRules(cfg.project.Ask, Ask, tool, input, cfg):
		return decision(Ask, "rule.project.ask", "项目规则要求确认: "+tool)
	case mode == ModeReadOnly:
		if cap.ReadOnly {
			return decision(Allow, "mode.read_only", "只读模式放行只读工具")
		}
		return readonlyDeny(tool)
	case matchRules(cfg.project.Allow, Allow, tool, input, cfg):
		return decision(Allow, "rule.project.allow", "项目规则放行: "+tool)
	}
	if ruleID, ok := preapproved(ctx, cfg, tool, input); ok {
		return decision(Allow, ruleID, "预批放行: "+tool)
	}
	return s.checkFallback(cfg, tool, input, cap)
}

// checkFallback 兜底段：会话授权 → 只读放行 → 默认确认。
// （配置白名单已前移至 checkStandard 的 break-glass 位次。）
func (s *Service) checkFallback(cfg config, tool string, input any, cap Capability) Decision {
	switch {
	case matchRules(s.sessionRuleSet().Allow, Allow, tool, input, cfg):
		// 会话授权同样覆盖普通工具的 ask 兜底（比 ZCode 只在 alwaysAsk 段查
		// 会话规则更完整——用户点了「总是允许」不该再被问）
		return decision(Allow, "rule.session.allow", "本会话已授权: "+tool)
	case cap.ReadOnly:
		return decision(Allow, "cap.readOnly", "只读工具放行")
	default:
		return decision(Ask, "mode.default", "默认确认: "+tool)
	}
}

func preapproved(ctx context.Context, cfg config, tool string, input any) (string, bool) {
	if cfg.preapprove == nil {
		return "", false
	}
	ruleID, ok := cfg.preapprove(ctx, tool, input)
	return ruleID, ok && ruleID != ""
}

// AllowForSession 会话级授权登记（用户对 ask 选择「本会话总是允许」时调用）。
// 同 (tool, content) 重复登记折叠（#70）：规则表=授权真相——N 次「总是允许」
// 不该积累 N 条相同规则（线性膨胀稀释审计面）。
func (s *Service) AllowForSession(tool, content string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.sessionRules.Allow {
		if r.ToolName == tool && r.Content == content {
			return
		}
	}
	s.sessionRules.Allow = append(s.sessionRules.Allow, Rule{ToolName: tool, Content: content})
}

// SessionAllows 本会话已授权清单快照（#70 审计面）：锁内深拷贝，调用方可安全
// 遍历/导出；空清单返回 nil。
func (s *Service) SessionAllows() []Rule {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sessionRules.Allow) == 0 {
		return nil
	}
	out := make([]Rule, len(s.sessionRules.Allow))
	copy(out, s.sessionRules.Allow)
	return out
}

// ResetSession 会话结束清空会话授权（实例消亡语义的显式形态）。
func (s *Service) ResetSession() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessionRules = Ruleset{}
}

func (s *Service) sessionRuleSet() *Ruleset {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.sessionRules
	return &r
}

// matchRules 任一规则命中即 true。pol 为规则所在档位：决定复合命令拆段后的
// 段级量词（Allow=每段命中，Deny/Ask=任一段命中——各自的 fail-closed 侧）。
//
// #86 fail-loud：deny 档且规则带内容、而输入是 map/struct 形态却提取不出任何
// subject 面（字段名全在 SubjectKeys 清单外——宿主 schema 与清单脱节）时，
// 该规则对此调用形同虚设且判定会流向后续档位——这是 deny 规则最坏的失效形态
// （静默死字），经 cfg.warn 显式暴露。allow/ask 失配落 ask 兜底本就保守，
// 不告警；字符串/nil 输入不告警（前者本身即匹配对象，后者根本没带内容，
// 「带内容的规则对它们失配」是规则与工具形态的正常错位，不是清单盲区）。
func matchRules(rules []Rule, pol Behavior, tool string, input any, cfg config) bool {
	faces := subjects(input, cfg.subjectKeys)
	for _, r := range rules {
		if !matchToolName(r.ToolName, tool, cfg.equiv) {
			continue
		}
		if matchRuleContent(r.Content, faces, pol) {
			return true
		}
		if pol == Deny && r.Content != "" && len(faces) == 0 && structuredInput(input) && cfg.warn != nil {
			cfg.warn(fmt.Sprintf(
				"permgate: 工具 %s 的 deny 内容规则 %q 无法评估——输入不含 subject 清单内任何字段（清单=%v）；"+
					"若输入 schema 用其他字段名，请配置 Service.SubjectKeys",
				tool, r.Content, cfg.subjectKeys))
		}
	}
	return false
}

// matchToolName 工具名匹配：精确相等，或等价钩子判定。钩子已在 snapshot 解析
// （nil → DefaultToolEquivalence，即原「Edit 规则匹配 Write」ZCode 特例，#86
// 把它从判定链烘焙改为宿主可配）。
func matchToolName(ruleTool, tool string, equiv func(a, b string) bool) bool {
	if ruleTool == tool {
		return true
	}
	return equiv(ruleTool, tool)
}

// DefaultToolEquivalence 写面等价的缺省实现（#86 外置；对标 ZCode 同款特例）：
// Edit 规则匹配 Write 调用——两个工具是同一「写文件」入口的两种形态，针对
// Edit 书写的规则对 Write 同样生效。**单向**：Write 规则不匹配 Edit（规则按
// 其声明的入口书写）。a 为规则声明的工具名，b 为实际调用的工具名；精确相等
// 不经本函数（matchToolName 先判）。宿主工具命名不同（EditFile/ApplyPatch …）
// 时经 Service.ToolEquivalence 换上自己的等价语义。
func DefaultToolEquivalence(ruleTool, tool string) bool {
	return ruleTool == "Edit" && tool == "Write"
}

// structuredInput 输入是否为字段化形态（map / struct，解指针后判断）。
// #86 的失配告警只看这类输入：字符串输入本身即匹配对象（永远有面），nil/标量
// 输入根本没带内容——「带内容的 deny 规则对它们失配」是规则与工具形态的正常
// 错位，告警只会制造噪音；只有「输入带了字段、字段名却全在清单外」才是
// SubjectKeys 脱节的信号。
func structuredInput(input any) bool {
	switch input.(type) {
	case map[string]any, map[string]string:
		return true
	}
	rv := reflect.ValueOf(input)
	for rv.IsValid() && rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return false
		}
		rv = rv.Elem()
	}
	if !rv.IsValid() {
		return false
	}
	switch rv.Kind() {
	case reflect.Map, reflect.Struct:
		return true
	}
	return false
}

// defaultSubjectKeys Service.SubjectKeys 零值对应的缺省清单（与 ruleSubjects
// 清单同步）。⚠️ 这是 ZCode 的领域词汇惯例（#86），不是普遍契约：工具输入
// schema 用其他字段名的宿主必须配置 Service.SubjectKeys，否则清单外字段是
// 匹配盲区（deny 规则静默失效——该失效形态的 fail-loud 出口见 matchRules）。
// file_path/path 类 subject 先 filepath.Clean 再匹配：wildcard 路径规则
// （"/repo/data/*"）可被 `..` 穿越与重复分隔符绕过，Clean 后
// "/repo/data/../../etc/passwd" 归一为 "/etc/passwd"，不再误命中（fail-closed；
// 第六轮审计）。符号链接绕过须执行器侧 EvalSymlinks 治理——本包不做文件系统
// 访问，保持纯函数判定；该治理的单源见 sandbox.FSFence（guardx#117）。
// command 字段按复合命令拆段（#62），其余字段单段。
var defaultSubjectKeys = []string{"command", "url", "file_path", "path", "pattern", "patch_text"}

// pathSubjectKeys 匹配前须 Clean 的路径类字段。
var pathSubjectKeys = map[string]bool{"file_path": true, "path": true}

// commandKey 按复合命令操作符拆段的命令形态字段。
const commandKey = "command"

// subjectFace 一个匹配面：command 形态是复合命令拆出的段（≥1），其余形态恒
// 单段。面内多段来自同一条 shell 命令串的拆分，量词语义见 matchRuleContent。
type subjectFace []string

// subjects 从工具输入提取匹配对象（对标 ruleSubjects 的字段清单，键名按 keys
// ——Check 路径传 snapshot 解析后的清单；keys 为空时落缺省，直调兜底）。
// 多面语义（v0.10.38）：同一输入的 command/url/file_path/… 全部参与匹配——
// 此前命中首个字段即返回，含 command+file_path 的输入里路径规则永不生效。
// 类型化输入（#65/#72）：map[string]string 与 struct（含指针、匿名嵌入、
// json tag）同样按字段名提取——此前静默落 nil，内容级 deny 对类型化调用方
// 全部失配（fail-open，实测 deny 绕过）。
func subjects(input any, keys []string) []subjectFace {
	if len(keys) == 0 {
		keys = defaultSubjectKeys
	}
	switch v := input.(type) {
	case string:
		// 字符串输入本身即命令形态（bash 类工具的主通道）——同样拆段，
		// 否则 #62/#71 的复合形态从主入口绕过。
		return []subjectFace{subjectFace(splitCommand(v))}
	case map[string]any:
		return mapSubjects(keys, func(key string) (string, bool) { s, ok := v[key].(string); return s, ok })
	case map[string]string:
		return mapSubjects(keys, func(key string) (string, bool) { s, ok := v[key]; return s, ok })
	}
	return reflectSubjects(input, keys)
}

// mapSubjects 按 keys 顺序（确定性遍历，command 优先）从 lookup 提取。
func mapSubjects(keys []string, lookup func(string) (string, bool)) []subjectFace {
	var faces []subjectFace
	for _, key := range keys {
		if s, ok := lookup(key); ok && s != "" {
			faces = append(faces, keyFace(key, s))
		}
	}
	return faces
}

// keyFace 按字段形态构造匹配面：command 拆段；路径类先 Clean；其余单段原样。
func keyFace(key, s string) subjectFace {
	if key == commandKey {
		return subjectFace(splitCommand(s))
	}
	if pathSubjectKeys[key] {
		s = filepath.Clean(s)
	}
	return subjectFace{s}
}

// reflectSubjects 类型化输入的兜底提取（#65）：struct（解指针、含匿名嵌入）
// 按 json tag/字段名对 keys 提取 string 字段；string 键的 map 提取 string 值。
// 提取不到返回 nil（该输入确实不含内容字段）。
func reflectSubjects(input any, keys []string) []subjectFace {
	rv := reflect.ValueOf(input)
	for rv.IsValid() && rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return nil
		}
		rv = rv.Elem()
	}
	if !rv.IsValid() {
		return nil
	}
	switch rv.Kind() {
	case reflect.Struct:
		return structSubjects(rv, keys, 3) // 限深防病态自嵌套
	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			return nil
		}
		return mapSubjects(keys, func(key string) (string, bool) {
			mv := rv.MapIndex(reflect.ValueOf(key))
			if !mv.IsValid() {
				return "", false
			}
			return stringValue(mv)
		})
	}
	return nil
}

// structSubjects 按 keys 顺序提取 struct 的 string 字段。
func structSubjects(rv reflect.Value, keys []string, depth int) []subjectFace {
	if depth <= 0 {
		return nil
	}
	var faces []subjectFace
	for _, key := range keys {
		if s, ok := structFieldString(rv, key, depth); ok {
			faces = append(faces, keyFace(key, s))
		}
	}
	return faces
}

// structFieldString 找到与 key 匹配的字段（json tag 优先，字段名去下划线
// 小写比对——Command/COMMAND/file_path/FilePath 均命中）并取 string 值。
// 匿名嵌入 struct 递归查找。
func structFieldString(rv reflect.Value, key string, depth int) (string, bool) {
	norm := normalizeFieldName(key)
	t := rv.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Anonymous && f.Type.Kind() == reflect.Struct {
			if s, ok := structFieldString(rv.Field(i), key, depth-1); ok {
				return s, true
			}
			continue
		}
		if f.PkgPath != "" {
			continue // 未导出字段不读
		}
		name := f.Name
		if tag, ok := f.Tag.Lookup("json"); ok {
			if n := strings.Split(tag, ",")[0]; n != "" {
				if n == "-" {
					continue
				}
				name = n
			}
		}
		if normalizeFieldName(name) != norm {
			continue
		}
		if s, ok := stringValue(rv.Field(i)); ok && s != "" {
			return s, true
		}
	}
	return "", false
}

// stringValue 解出 reflect 值的 string 形态（解接口/指针；非 string 返回 false）。
func stringValue(v reflect.Value) (string, bool) {
	for v.Kind() == reflect.Interface || v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return "", false
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.String {
		return "", false
	}
	return v.String(), true
}

// normalizeFieldName 字段名归一比对：小写、去下划线（file_path ↔ FilePath）。
func normalizeFieldName(s string) string {
	return strings.ReplaceAll(strings.ToLower(s), "_", "")
}

// splitCommand 按 shell 复合命令操作符拆段（#62/#71/#129）：`;` `&`（含
// `&&`——后台控制操作符，不带引号时真实 shell 在此分命令）`||` `|` 与换行；
// 引号内（'…' / "…"，反斜杠转义）不拆；段首尾空白剥除、空段丢弃。
// 无操作符时返回单段（首尾空白已剥）。不实现完整 shell 语法（命令替换、
// heredoc 等真 AST 形态归 tools/bashguard）——本切分的目标是 fail-closed：
// 让 allow 侧「每段都在名单里才放行」，操作符后的命令不得搭车；deny 侧
// 「任一段命中即拦」，换行不再把 `rm\n-rf /` 藏过前缀规则。
func splitCommand(cmd string) []string {
	var (
		segs     []string
		cur      strings.Builder
		inSingle bool
		inDouble bool
	)
	flush := func() {
		if t := strings.TrimSpace(cur.String()); t != "" {
			segs = append(segs, t)
		}
		cur.Reset()
	}
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		switch {
		case inSingle:
			if c == '\'' {
				inSingle = false
			}
			cur.WriteByte(c)
		case inDouble:
			switch c {
			case '\\':
				// 双引号内反斜杠转义下一字符（对分隔符判定只需吞掉它）
				if i+1 < len(cmd) {
					cur.WriteByte(c)
					i++
					cur.WriteByte(cmd[i])
				} else {
					cur.WriteByte(c)
				}
			case '"':
				inDouble = false
				cur.WriteByte(c)
			default:
				cur.WriteByte(c)
			}
		default:
			switch c {
			case '\\':
				// 未加引号的 \x 视作字面 x（\; 不拆段）；原文保留，段内容与
				// 输入逐字节一致（精确规则按可见命令文本书写）
				cur.WriteByte(c)
				if i+1 < len(cmd) {
					i++
					cur.WriteByte(cmd[i])
				}
			case '\'':
				inSingle = true
				cur.WriteByte(c)
			case '"':
				inDouble = true
				cur.WriteByte(c)
			case ';', '\n', '|', '&':
				// `||` 与 `|` 同为分隔：相邻分隔产生的空段由 flush 丢弃。
				// `&` 同为分隔（guardx#129）：POSIX shell 的后台控制操作符，
				// 不带引号时真实 shell 恰恰在此分命令——`git status & rm -rf /`
				// 的 rm 段不得搭 allow 的车、不得藏过 deny 前缀。「单个 & 是
				// URL 常客」的理由只对带引号的 URL 成立（引号内本就不拆，
				// inSingle/inDouble 已保护）。`&&` 的两个 & 各自触发一次
				// flush，空段由 flush 丢弃，与旧的 && 特判等价。
				flush()
			default:
				cur.WriteByte(c)
			}
		}
	}
	flush()
	return segs
}

// matchRuleContent 内容模式匹配：空模式=全匹配（该工具全部调用）。
// 每个匹配面（face）是一组段——command 形态复合命令按操作符拆段，其余单段。
// 面内量词按极性取 fail-closed 侧（#62）：Allow 要求**每段**命中（任一段不在
// 名单即整体失配——操作符后的命令不得搭车放行）；Deny/Ask 只要**任一段**命中
// （复合命令混进一段危险命令即拦/即问）。任一面命中即规则命中（多面语义
// v0.10.38 不变）。
func matchRuleContent(content string, faces []subjectFace, pol Behavior) bool {
	if content == "" {
		return true
	}
	prefix := strings.TrimSuffix(content, ":*")
	isPrefix := prefix != content
	for _, face := range faces {
		if len(face) == 0 {
			continue
		}
		if faceMatch(face, content, prefix, isPrefix, pol) {
			return true
		}
	}
	return false
}

// faceMatch 单面命中：Allow 全段命中（universal），Deny/Ask 任一段命中
// （existential）——两个方向都是各自的保守侧。
// Allow 侧另有两道守门（guardx#144/#161）：段内含命令替换/参数展开面
// （$(`、反引号、`${`）或未加引号包裹的重定向操作符（`>` `<`）时该段恒失配
// ——allow 前缀按字面文本核对，替换体的真实命令在运行期才展开、重定向目标
// 路径不在规则审视面内（`git status $(curl evil)` / `git status > /etc/passwd`
// 搭 `git status:*` 的车曾原样放行，与「拆不动的形态宁可失配」的包注释承诺
// 相反；deny/ask 不受影响，仍按既有保守语义）。
func faceMatch(face subjectFace, content, prefix string, isPrefix bool, pol Behavior) bool {
	if pol == Allow {
		for _, seg := range face {
			if hasCommandSubstitution(seg) || hasRedirect(seg) || !segMatch(content, prefix, isPrefix, seg) {
				return false
			}
		}
		return true
	}
	for _, seg := range face {
		if segMatch(content, prefix, isPrefix, seg) {
			return true
		}
	}
	return false
}

// segMatch 单段匹配：`p:*` 前缀（空白边界）/ 含 * 通配 / 精确。
func segMatch(content, prefix string, isPrefix bool, sub string) bool {
	switch {
	case isPrefix && prefixBoundary(sub, prefix):
		return true
	case !isPrefix && strings.Contains(content, "*") && wildcardMatch(content, sub):
		return true
	case !isPrefix && sub == content:
		return true
	}
	return false
}

// hasCommandSubstitution 报告段内是否存在命令替换/参数展开面（`$(`、反引号、
// `${`——guardx#144 的 allow 守门）。扫描口径：
//   - 单引号内是字面（不计数）——shell 语义，`'$(x)'` 原样传递；
//   - 双引号内 `$(…)` 与反引号**照样执行**、`${…}` 照样展开（双引号不是
//     护身符，计数）；
//   - 反斜杠转义的 `\$`、`\“、`\${` 为字面（不计数）。
func hasCommandSubstitution(seg string) bool {
	inSingle := false
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		switch {
		case inSingle:
			if c == '\'' {
				inSingle = false
			}
		case c == '\\':
			i++ // 转义下一字符（与 splitCommand 的 \x 字面化同口径）
		case c == '\'':
			inSingle = true
		case c == '$' && i+1 < len(seg) && (seg[i+1] == '(' || seg[i+1] == '{'):
			return true
		case c == '`':
			return true
		}
	}
	return false
}

// hasRedirect 报告段内是否存在未加引号包裹的重定向操作符（`>` `<`——guardx#161
// 的 allow 守门；`>>` `2>` `2>&1` `>|` `<<` 均由这两个字符覆盖，`&>` 里的 `&`
// 已被 splitCommand 拆段、段内只剩 `>`）。扫描口径——与 hasCommandSubstitution
// 有一处刻意不同，勿照抄：
//   - 单引号内是字面（不计数）——shell 语义，`'a>b'` 原样传递；
//   - 双引号内也是字面（不计数）——双引号内的 `>` 不构成重定向；而 `$(` 在
//     双引号内照样执行，所以那边不能豁免。若照抄替换体守门的双引号口径，
//     `git status "a>b"` 这类正常形态会被误伤（落 ask）；
//   - 反斜杠转义的 `\>`、`\<` 为字面（不计数）。
//
// 段内命中 ⇒ 该段 allow 恒失配（落 ask）：重定向目标路径完全不在规则审视面内，
// `git status > /etc/passwd` 搭 `git status:*` 的车等于「往任意路径写任意内容」。
// deny/ask 侧不调用本函数，仍按既有保守语义。
func hasRedirect(seg string) bool {
	inSingle := false
	inDouble := false
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		switch {
		case inSingle:
			if c == '\'' {
				inSingle = false
			}
		case inDouble:
			switch c {
			case '\\':
				i++ // 双引号内反斜杠转义下一字符（主要为了 \" 不提前收尾）
			case '"':
				inDouble = false
			}
		case c == '\\':
			i++ // 转义下一字符（\> 是字面）
		case c == '\'':
			inSingle = true
		case c == '"':
			inDouble = true
		case c == '>' || c == '<':
			return true
		}
	}
	return false
}

// prefixBoundary 前缀边界（#71）：prefix 之后是空白（unicode.IsSpace——含空格、
// 制表、换行、回车等）即命中。换行同属 shell 命令分隔，不得作为「前缀不匹配」
// 的藏身处；边界同时防 `git statusx` 这类前缀 bleed。
func prefixBoundary(sub, prefix string) bool {
	if !strings.HasPrefix(sub, prefix) {
		return false
	}
	rest := sub[len(prefix):]
	if rest == "" {
		return true
	}
	r, _ := utf8.DecodeRuneInString(rest)
	return unicode.IsSpace(r)
}

// wildcardCache `*` 通配匹配正则的编译缓存（键=pattern）。单飞去重：并发首次
// 命中同一 pattern 时只编译一次，其余请求共享结果。
//
// TTL=0 ⇒ 永不过期，且不引入后台清扫 goroutine（与原 sync.Map 无常驻协程一致）。
var wildcardCache = cache.NewSingleFlightCache(cache.NewLocalCache[regexp.Regexp](cache.LocalConfig[regexp.Regexp]{
	NullTTL: -1, // 编译失败走 err 分支本就不写 null marker；显式禁用空值缓存，杜绝「查不到」被误当缓存事实
}))

// wildcardMatch `*` 通配匹配（* 跨任意字符——含换行，(?s)：整条值是匹配对象，
// 多行值不得因 `.` 不吃换行而漏配 #71；其余字面）。
func wildcardMatch(pattern, s string) bool {
	re, err := wildcardCache.GetOrLoadWithSource(context.Background(), pattern, func(_ context.Context, p string) (*regexp.Regexp, error) {
		quoted := regexp.QuoteMeta(p)
		return regexp.Compile(`(?s)^` + strings.ReplaceAll(quoted, `\*`, ".*") + `$`)
	})
	if err != nil || re == nil {
		return false
	}
	return re.MatchString(s)
}
