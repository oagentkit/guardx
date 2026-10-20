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
// 宿主声明的强度与实际执行的强度之间一旦没有信号，档位这套机制就是装饰。
func (r *Registry) Resolve(min Level) (Provider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var best Provider
	for _, p := range r.providers {
		if !p.Level().AtLeast(min) {
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
func Execute(ctx context.Context, reg *Registry, min Level, req Request) (Outcome, error) {
	p, err := reg.Resolve(min)
	if err != nil {
		return Outcome{}, err
	}
	return p.Exec(ctx, req)
}
