// backend.go —— 票据状态存储接缝（issue #145 多副本部署）。
//
// # 为什么要把状态抽出来
//
// 原实现把判定与状态焊在一起（mu + map）：签发/消费的判定语义正确，
// 但状态只活在本进程里——多副本宿主在副本 A 签发的票据，副本 B 消费时
// 找不到，一次性短时授权的防重放语义跨副本失效。抽成 Backend 之后：
// **判定逻辑（TTL、单次消费、容量策略的调用时机）留在 Store，跨进程状态
// 由宿主接 DB / 协调后端**——与 sideeffect.Acquire「判定归包内、原子性归
// 存储」同一条分工。
//
// # 跨进程实现的硬要求（原子性契约）
//
//   - **Take 必须原子**：多副本并发 Take 同一 id，恰好一个返回 ok=true。
//     DB 形态 = `DELETE ... RETURNING`（或等价事务）；Redis 形态 = Lua。
//     判定「过期则失败」也在同一次取出里完成——先查后删的两步形态会把
//     「两个副本同时消费」的窗口重新打开，正是本包要防的那件事。
//   - **Put 写入即可见**，同 id 覆盖（与进程内语义一致；id 是 192 bit
//     随机，碰撞不在现实里）。
//   - GC / Len 是清理与观测面，一致性要求弱于 Take。
//
// # 时间的真相只有存储一个（issue #186）
//
// **节点时钟不得参与过期判定。** 多副本部署下各节点时钟必然有偏移：
// 快 30s 的副本会把未过期票据判成过期（旧实现先删后判——这次误判同时
// 删掉了票，真正持有者随后消费失败且不可恢复）；慢的副本则让过期票据
// 仍可重放。这不是「略有偏差」，是把「票据是否过期」的语义交给了一台
// 随时会漂的机器。
//
// 故时间权威在 **Backend**：
//
//   - `Put(id, binding, ttl)` 按**存储时钟**落 expires_at，并返回该时刻
//     （Issue 原样返回给宿主，库里记的与宿主看到的是同一个时刻）；
//   - `Take(id)` / `GC()` 不带任何时间参数，过期比较**只能**用存储时钟。
//     接口层面根本没有接收节点时钟的入口——不是靠实现自觉忽略它。
//
// 实现形态：PostgreSQL → 事务内 `clock_timestamp()`（或 `now() + ttl`
// 在同一语句里落库并 RETURNING）；Redis → Lua 脚本内 `TIME`；
// 进程内参考实现 → 构造时注入的时钟（`NewMemoryBackendWithClock`，
// 它就是单进程的「存储时钟」，也是过期语义可确定性测试的接缝）。
// `examples/pgstore` 的「到期由存储时钟算」（#140/#194）是同一口径。
//
// # 进程内参考实现
//
// NewMemoryBackend：单进程成立，**不得上生产**（跨进程原子性它给不了）。
// 它的职责是把判定逻辑垫在契约之下，让契约可测——与 coord 的内存后端、
// examples/pgstore 对 taskboard 的分工同口径（内核证契约，宿主接生产）。
package ticket

import (
	"fmt"
	"sync"
	"time"
)

// Backend 票据状态存储（并发安全；原子性契约见文件头）。
//
// 实现可以是进程内的（MemoryBackend）、SQL 的、Redis 的——本包只依赖
// 这四个操作的语义，不依赖它们怎么达成。**过期判定的时间权威在实现侧**
// （存储时钟，见文件头「时间的真相只有存储一个」）：接口不接收调用方时间，
// 节点时钟因此没有进入判定面的路径。
type Backend interface {
	// Put 写入一张未消费票据，expires_at 由**存储时钟** + ttl 落下，
	// 并返回该时刻（Issue 原样返回给宿主）。
	//
	// 容量策略由实现自判（内存参考实现满了报错，与旧实现「票据空间已满」
	// 同一拒发口径）。
	//
	// 签发路径（Store.Issue）在 Put 前先经 GC 回收过期票据（issue #208）：
	// 实现看到的容量压力以未过期票据为主——实现自身的容量判据不必分辨
	// 过期与否（它拿到的 ttl 与存储时钟足以在落库时判，但容量口径归实现）。
	Put(id string, binding Binding, ttl time.Duration) (expiresAt time.Time, err error)
	// Take 原子取出并删除：不存在或已过期（**存储时钟**）⇒ ok=false。
	//
	// ⚠️ 过期票据**也已被删除**——与进程内旧实现「消费尝试顺手清过期」
	// 逐字一致（先删后判的顺序是语义的一部分，不是实现巧合）。时钟权威
	// 归存储之后，这一条不再有「误删尚未过期的票」的窗口。
	Take(id string) (Binding, bool, error)
	// GC 删除已过期票据（**存储时钟**），返回清理张数。
	GC() (int, error)
	// Len 返回现存票据数（含过期未清理的——它们只是不可消费，仍占空间）。
	Len() (int, error)
}

// memoryBackend 进程内参考实现（并发安全；单进程成立，不得上生产）。
type memoryBackend struct {
	mu      sync.Mutex
	m       map[string]entry
	maxSize int
	// now 存储时钟：本实现就是「单进程的存储」，注入的时钟是过期判定的
	// 唯一时间真相（issue #186）。生产宿主接 DB 时，这个角色由数据库
	// 的 clock_timestamp / Lua TIME 承担。
	now func() time.Time
}

// NewMemoryBackend 构造进程内参考实现（maxSize <= 0 ⇒ DefaultMaxEntries）。
//
// 存储时钟取 time.Now；需要确定性过期语义（测试）用
// NewMemoryBackendWithClock 注入时钟。
//
// 这是 Store 缺省构造（New）背后的实现；宿主的跨进程 Backend 由宿主
// 自己实现并经 NewWithBackend 注入。
func NewMemoryBackend(maxSize int) Backend {
	return NewMemoryBackendWithClock(maxSize, time.Now)
}

// NewMemoryBackendWithClock 构造进程内参考实现并注入**存储时钟**。
//
// ⭐ 为什么时钟在 Backend 而不是 Store：过期判定必须只有一个时间真相。
// 旧实现让调用方把 now 传进 Take/GC，多副本下「谁的时钟说了算」取决于
// 这次调用是谁发的——快时钟误杀、慢时钟放行重放。时钟注入到存储侧之后，
// 进程内参考实现与跨进程 DB 遵守同一条语义（DB 用存储时钟），测试也能
// 确定性地推进过期（不靠 sleep）。
//
// **本实现不会在持有内部锁时调用该回调**（issue #317）：now 在进入临界区
// 之前取值，回调里重入本包的 Put/Take/GC/Len 不会撞上不可重入的互斥锁。
// 宿主可以放心在时钟闭包里读票据数或其他本包接口。
//
// # 接缝契约（issue #369）
//
// @seam: no-reentry no-blocking panic-caller
//
//   - **不得重入**：回调内不得再次触发会读取后端时钟的写路径（会递归）；
//     只读回查是安全的（时钟在 b.mu 之外被调用，issue #317）。
//   - **不得阻塞**：回调在每次过期判定前被调用，必须立即返回。
//   - **panic 由调用方兜**（panic-caller）：内核不 recover 该回调的 panic。
//
// maxSize <= 0 ⇒ DefaultMaxEntries；now 为 nil ⇒ time.Now。
func NewMemoryBackendWithClock(maxSize int, now func() time.Time) Backend {
	if maxSize <= 0 {
		maxSize = DefaultMaxEntries
	}
	if now == nil {
		now = time.Now
	}
	return &memoryBackend{m: map[string]entry{}, maxSize: maxSize, now: now}
}

// Put 写入；容量已满 ⇒ 显式报错（与旧实现同一口径：满了就说满，不默默淘汰）。
// expires_at 按**存储时钟** + ttl 计算，返回同一个时刻。
//
// 存储时钟在**锁外**取值（issue #317）：时钟是宿主注入的回调，持锁调用它
// 会让「回调里重入本包」变成永久死锁。
func (b *memoryBackend) Put(id string, binding Binding, ttl time.Duration) (time.Time, error) {
	exp := b.now().Add(ttl)
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.m) >= b.maxSize {
		return time.Time{}, fmt.Errorf("票据空间已满（上限 %d 张）", b.maxSize)
	}
	b.m[id] = entry{binding: binding, expiresAt: exp}
	return exp, nil
}

// Take 原子取出并删除（单锁内完成取/删/判过期，顺序与旧 Consume 逐字一致）。
// 过期比较只读**存储时钟**——节点时钟在接口层面就无法传进来（issue #186）。
// 时钟回调在锁外调用（issue #317）。
func (b *memoryBackend) Take(id string) (Binding, bool, error) {
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	tk, ok := b.m[id]
	if !ok {
		return Binding{}, false, nil
	}
	delete(b.m, id)
	if now.After(tk.expiresAt) {
		return Binding{}, false, nil
	}
	return tk.binding, true, nil
}

// GC 清掉过期票据（按**存储时钟**判；时钟回调在锁外调用，issue #317）。
func (b *memoryBackend) GC() (int, error) {
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for id, tk := range b.m {
		if now.After(tk.expiresAt) {
			delete(b.m, id)
			n++
		}
	}
	return n, nil
}

// Len 现存票据数（含过期未清理的）。
func (b *memoryBackend) Len() (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.m), nil
}
