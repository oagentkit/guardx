package sandbox

import (
	"context"
	"sort"
	"sync"

	"github.com/oekit/pkg/errors"
)

// ErrNoProvider 没有任何已登记的后端达到要求的隔离档位。
var ErrNoProvider = errors.New("sandbox: 没有已登记的执行后端达到要求的隔离档位")

// ErrDuplicateProvider 登记了重复的后端标识。
var ErrDuplicateProvider = errors.New("sandbox: 执行后端标识重复")

// Registry 后端登记簿。
//
// 并发安全：Register 与 Resolve 可并发调用。
type Registry struct {
	mu        sync.RWMutex
	providers []Provider
}

// NewRegistry 空登记簿。
func NewRegistry() *Registry { return &Registry{} }

// Register 登记一个后端。
//
// 重复标识即拒：两个后端同标识时，按标识选中哪一个取决于登记顺序——而
// 「选中哪个后端」直接决定这次执行的实际隔离强度。那是**装配期缺陷**，
// 不能留到执行期、靠某次恰好选对了来兜。
func (r *Registry) Register(p Provider) error {
	if p == nil {
		return errors.New("sandbox: 不能登记空后端")
	}
	id := p.ID()
	if id == "" {
		return errors.New("sandbox: 执行后端标识不得为空")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.providers {
		if e.ID() == id {
			return errors.Wrap(ErrDuplicateProvider, "sandbox: 登记失败", "provider_id", id)
		}
	}
	r.providers = append(r.providers, p)
	return nil
}

// Resolve 按要求档位选后端：选**最弱**满足者。
//
// budget 是**可选**的预算要求（省略即只看档位）。给了预算时，后端还必须能兑现
// 那组预算（见 Capable）才会被选中。
//
// # 为什么 budget 是可选参数而不是必填
//
// Provider 与本方法都已在 v0.9.0 发布——把 budget 加成必填参数是**破坏性变更**。
// 可选参数让既有调用点（Resolve(min)）**编译期零改动、行为逐字不变**：
// 省略 budget 时只看档位，与旧版一致。
//
// # 为什么选最弱而不是最强
//
// 要求档位是**下限**（「至少要这么强」），更强的后端成本更高（容器启动、虚拟机
// 拉起都要时间）。在满足下限的前提下取最弱的，是「够用且最省」。
//
// 要求写低了、于是拿到弱后端，那是宿主自己的声明，不是门禁的失败——本包不替
// 宿主抬高要求，也不替它降。
//
// # 没有满足者时拒绝，不降级
//
// 返回 ErrNoProvider。**绝不**退回一个弱后端继续跑——那正是本包要防的落差：
// 宿主声明的强度与实际执行的强度之间一旦没有信号，档位整套机制就是装饰。
//
// # 兜不住预算的后端是**不被选中**，不是选中后失败
//
// 这与「档位不足」的处置同一条纪律，但**成因不同**，处置也不同：
//
//	档位不足       ⇒ 环境里有更弱的后端（降级会掉强度）⇒ 拒绝
//	兜不住预算     ⇒ 环境里的后端都兑现不了这项要求 ⇒ 拒绝
//
// 两者都返回 ErrNoProvider，但宿主看到错误时该做的事不一样：前者可以「把要求降一档」
// （只要够用），后者只能「换执行模型」或「放弃这项要求」——降档解决不了它。
//
// # 多组预算怎么合并
//
// 传多个 Budget 时**逐项取要求更高者**（MaxCalls/MaxBytes/MaxMemory 取最大，
// WallClock 取最长）。合并不做「求和」——那是配额语义，不是上限语义。
func (r *Registry) Resolve(min Level, budget ...Budget) (Provider, error) {
	req := mergeBudgets(budget...)
	r.mu.RLock()
	defer r.mu.RUnlock()
	var best Provider
	for _, p := range r.providers {
		if !p.Level().AtLeast(min) {
			continue
		}
		if !supportsBudget(p, req) {
			continue
		}
		if best == nil || p.Level() < best.Level() {
			best = p
		}
	}
	if best == nil {
		return nil, errors.Wrap(ErrNoProvider, "sandbox: 无法选择执行后端", "required_level", min.String())
	}
	return best, nil
}

// mergeBudgets 合并多组预算要求：逐项取要求更高者。
//
// 求和是**配额**语义（这些项可累加），而这里是**上限**语义（每一项各自封顶），
// 故取最大值而非求和。
func mergeBudgets(budgets ...Budget) Budget {
	var out Budget
	for _, b := range budgets {
		if b.WallClock > out.WallClock {
			out.WallClock = b.WallClock
		}
		if b.MaxCalls > out.MaxCalls {
			out.MaxCalls = b.MaxCalls
		}
		if b.MaxBytes > out.MaxBytes {
			out.MaxBytes = b.MaxBytes
		}
		if b.MaxMemory > out.MaxMemory {
			out.MaxMemory = b.MaxMemory
		}
	}
	return out
}

// supportsBudget 报告后端能否兑现这组预算。
//
// **未实现 Capable 的后端只兑现基本三闸、不兑现内存**（见 Capable 的缺省语义）：
// 这是保守的一侧——漏声明得到的是「兜不住」，不是「兜得住」。
func supportsBudget(p Provider, b Budget) bool {
	if c, ok := p.(Capable); ok {
		return c.Supports(b)
	}
	return SupportsBasic(b)
}

// Providers 已登记的后端快照，按档位升序、同档位按标识升序。
//
// 排序是为了让「当前登记了什么」有稳定答案：Go 的 map 迭代顺序是随机的，
// 而宿主要把这份清单打印进审计记录或配置文件——顺序每次都变的话，那份记录
// 就没法拿来做两次之间的对比。
func (r *Registry) Providers() []Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Provider, len(r.providers))
	copy(out, r.providers)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Level() != out[j].Level() {
			return out[i].Level() < out[j].Level()
		}
		return out[i].ID() < out[j].ID()
	})
	return out
}

// Execute 按要求档位选后端并执行一次程序。
//
// 这是原语侧的统一执行入口：要求档位 → 选后端 → 执行，三步在一处，
// 于是「这次执行实际跑在什么档位上」有唯一答案。
//
// # 预算要求从 Request 里取
//
// req.Budget 是这次执行的预算要求，它**同时用于选后端**——否则「要求了内存兜底
// 而后端兜不住」这件事就只在执行期暴露，而选后端这一步本可以拦下它。
//
// 既有调用方的 req.Budget.MaxMemory 是 0（新字段的零值 = 不要求内存），
// 故**行为逐字不变**。
func Execute(ctx context.Context, reg *Registry, min Level, req Request) (Outcome, error) {
	p, err := reg.Resolve(min, req.Budget)
	if err != nil {
		return Outcome{}, err
	}
	return p.Exec(ctx, req)
}
