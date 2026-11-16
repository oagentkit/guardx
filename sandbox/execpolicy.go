package sandbox

import (
	"path"
	"path/filepath"
	"strings"

	"github.com/oekit/pkg/errors"
)

// 容器执行硬约束面的判据错误（哨兵，调用方按需分派处置——比如装配期把
// 「镜像未钉 digest」映射为配置错误，把「挂载越界」映射为拒绝执行）。
//
// 每类失败一个哨兵：判据的错误文本是给人看的，**可判定事实走 errors.Is**。
// 拿文本当判据的调用方在文案一改时就静默失效，那正是本包要消灭的形态。
var (
	// ErrImageNotPinned 镜像引用没带 digest（浮动 tag 不可复现：同名 tag 重推
	// 之后「钉住什么就跑什么」不再成立）。
	ErrImageNotPinned = errors.New("sandbox: 镜像引用必须带 digest（不认 tag）")
	// ErrImageDigestNotAllowed 镜像 digest 不在白名单内。
	ErrImageDigestNotAllowed = errors.New("sandbox: 镜像 digest 不在白名单内")
	// ErrMountSourceNotAllowed 挂载源不在白名单内（或落在控制面 socket 上）。
	ErrMountSourceNotAllowed = errors.New("sandbox: 挂载源不在白名单内")
	// ErrMountTargetNotAllowed 挂载目标不在白名单内。
	ErrMountTargetNotAllowed = errors.New("sandbox: 挂载目标不在白名单内")
	// ErrMountNotReadOnly 策略要求只读而挂载声明了可写。
	ErrMountNotReadOnly = errors.New("sandbox: 挂载必须只读")
	// ErrRootfsNotReadOnly 策略要求只读 rootfs 而声明没有。
	ErrRootfsNotReadOnly = errors.New("sandbox: 要求只读 rootfs")
	// ErrRequireNonRoot 策略要求非 root 而声明没有。
	ErrRequireNonRoot = errors.New("sandbox: 要求非 root 用户执行")
	// ErrCapNotDropped 策略要求的 capability 没有被丢弃。
	ErrCapNotDropped = errors.New("sandbox: 要求的 capability 未丢弃")
	// ErrSeccompNotAllowed 策略指定的 seccomp profile 与声明不符。
	ErrSeccompNotAllowed = errors.New("sandbox: seccomp profile 不符合策略")
	// ErrLimitsExceeded 声明的资源上限超出策略（或缺失策略要求的限制）。
	ErrLimitsExceeded = errors.New("sandbox: 资源上限未落在策略内")
)

// controlSockets 控制面 socket：不论白名单怎么写都拒绝。
//
// 挂上它们不是「多暴露一个目录」，是把宿主的容器控制面交出去——作业可以在
// 里面创建任意特权容器，于是 network=none、只读 rootfs、cap_drop 全部失效。
// 这类路径的放行不该是配置自由度，故写死在判据里（白名单只能收紧，不能放宽）。
var controlSockets = []string{
	"/var/run/docker.sock",
	"/run/docker.sock",
	"/run/containerd/containerd.sock",
	"/var/run/crio/crio.sock",
	"/var/run/podman/podman.sock",
	"/var/run/containerd/containerd.sock",
	// Windows 控制面（#198）：Docker Desktop/引擎命名管道族——宿主容器控制面
	// 的 Windows 形态，与 unix socket 同等「挂上即交出控制面」的等级。
	`\\.\pipe\docker_engine`,
	`\\.\pipe\dockerDesktopLinuxEngine`,
	`\\.\pipe\dockerDesktopWindowsEngine`,
}

// ExecPolicy 容器执行的硬约束面：**值类型 + 纯判据**，不执行容器。
//
// # 与 Level / Budget 的分工
//
// Level 声明「要几档隔离」、Budget 声明「跑起来要花多少资源」，两者管的是
// **执行后端的选择与兑现**；ExecPolicy 管的是「这次执行声明本身是否落在策略
// 内」——挂载了哪些宿主路径、镜像是 digest 还是浮动 tag、rootfs 只读吗、
// 以什么用户跑、丢了哪些 capability、seccomp 用哪个 profile。这些事实在
// **选后端之前**就能判，判不过就不该交给任何后端。
//
// **兑现仍归 Provider**（真的 set caps drop、真的挂 seccomp、真的落 cgroup
// 限制）——本包不越界成容器运行时。本包给的是「声明面」与「策略面」之间的
// 可判定对照：宿主装配期能拦下的，不留到事后审计。
//
// # 零值即最严（fail-closed）
//
// 空策略的含义是**拒绝**而不是放行：
//   - ImageDigestAllow 为空 ⇒ 仍要求镜像带 digest（tag 一律拒）；
//   - MountSourceAllow 为空 ⇒ 任何挂载都拒（要挂载必须显式列出源）；
//   - 布尔项缺省 false ⇒ 不要求；一旦要求即必须声明满足。
//
// 方向是安全的那一侧：漏配策略拿到的是「挂载全拒」，不是「挂载全放」。
// 这与 Registry.Resolve 无满足者即拒绝执行是同一条纪律。
type ExecPolicy struct {
	// ImageDigestAllow 允许的镜像 digest 白名单（如 "sha256:abc…"；也接受
	// 裸 64 位 hex，按 sha256 归一）。空 = 只要求「引用必须带 digest」，
	// 不限定具体 digest。
	ImageDigestAllow []string
	// MountSourceAllow 允许的宿主挂载源白名单（精确匹配，filepath.Clean 后
	// 比较）。空 = 不允许任何挂载。控制面 socket 即使出现在白名单里也拒绝
	// （见 controlSockets）。
	MountSourceAllow []string
	// MountTargetAllow 允许的容器内挂载目标白名单（前缀匹配，path.Clean 后
	// 比较）。空 = 不限制目标（暴露面由源白名单主导）。
	MountTargetAllow []string
	// MountReadOnlyOnly 要求每个挂载都声明只读。
	MountReadOnlyOnly bool
	// ReadOnlyRootfs 要求声明只读 rootfs。
	ReadOnlyRootfs bool
	// RequireNonRoot 要求以非 root 用户执行。
	RequireNonRoot bool
	// CapDrop 要求声明丢弃的 capability 清单（大小写不敏感；"ALL" 覆盖一切）。
	// 空 = 不要求。
	CapDrop []string
	// SeccompProfile 要求的 seccomp profile 名（大小写不敏感；空 = 不要求）。
	SeccompProfile string
	// Limits 资源上限的策略面：每个非零项都要求声明侧 > 0 且 <= 策略值。
	// 零值 = 该项不要求。
	Limits Budget
}

// Spec 一次容器执行声明（声明面，不执行）。
//
// 字段与任务式执行后端（如内核 backend.Job）一一对应；由宿主在装配期把
// 自己的请求结构映射成 Spec 再交给 Judge。**本包不 import 任何执行后端**：
// 判据在这里，接法在宿主。
type Spec struct {
	// Image 镜像引用。must 带 digest（name@sha256:… 形态）；是否允许具体
	// digest 由 ExecPolicy.ImageDigestAllow 决定。
	Image string
	// Mounts 挂载声明。
	Mounts []Mount
	// RootfsReadOnly 声明 rootfs 只读。
	RootfsReadOnly bool
	// NonRoot 声明以非 root 用户执行。
	NonRoot bool
	// CapDrop 声明丢弃的 capability（如 ["ALL"]）。
	CapDrop []string
	// SeccompProfile 声明的 seccomp profile 名（空 = 未声明）。
	SeccompProfile string
	// Limits 声明的资源上限（零值 = 未声明该限制）。
	Limits Budget
}

// Mount 一条挂载声明。
type Mount struct {
	// Source 宿主侧来源路径。
	Source string
	// Target 容器内目标路径。
	Target string
	// ReadOnly 是否只读。
	ReadOnly bool
}

// Judge 判一次执行声明是否落在策略内；违反即返回对应哨兵错误（fail-closed）。
//
// 判定顺序即声明顺序：镜像 → 挂载（逐条）→ rootfs → 用户 → caps → seccomp
// → 资源上限。返回第一个违规项，错误里带具体值（便于定位是哪条声明）。
func (p ExecPolicy) Judge(s Spec) error {
	if err := p.judgeImage(s.Image); err != nil {
		return err
	}
	if err := p.judgeMounts(s.Mounts); err != nil {
		return err
	}
	if p.ReadOnlyRootfs && !s.RootfsReadOnly {
		return errors.Wrap(ErrRootfsNotReadOnly, "sandbox: 策略要求只读 rootfs，声明未置 RootfsReadOnly")
	}
	if p.RequireNonRoot && !s.NonRoot {
		return errors.Wrap(ErrRequireNonRoot, "sandbox: 策略要求非 root，声明未置 NonRoot")
	}
	if err := p.judgeCaps(s.CapDrop); err != nil {
		return err
	}
	if p.SeccompProfile != "" && !strings.EqualFold(s.SeccompProfile, p.SeccompProfile) {
		return errors.Wrap(ErrSeccompNotAllowed, "sandbox: seccomp profile 不符",
			"want", p.SeccompProfile, "got", s.SeccompProfile)
	}
	return p.judgeLimits(s.Limits)
}

// judgeImage 判镜像「带 digest」与「digest 在白名单内」两层。
func (p ExecPolicy) judgeImage(image string) error {
	digest, ok := splitDigest(image)
	if !ok {
		return errors.Wrap(ErrImageNotPinned, "sandbox: 镜像引用未带 digest", "image", image)
	}
	if len(p.ImageDigestAllow) == 0 {
		return nil
	}
	for _, allow := range p.ImageDigestAllow {
		if strings.EqualFold(normalizeDigest(allow), digest) {
			return nil
		}
	}
	return errors.Wrap(ErrImageDigestNotAllowed, "sandbox: 镜像 digest 不在白名单",
		"digest", digest)
}

// judgeMounts 逐条判挂载：源白名单 → 控制面 socket → 目标白名单 → 只读。
func (p ExecPolicy) judgeMounts(mounts []Mount) error {
	if len(mounts) > 0 && len(p.MountSourceAllow) == 0 {
		return errors.Wrap(ErrMountSourceNotAllowed, "sandbox: 策略未允许任何挂载（MountSourceAllow 为空）",
			"mounts", len(mounts))
	}
	for _, m := range mounts {
		src := filepath.Clean(m.Source)
		if src == "" || src == "." || src == string(filepath.Separator) {
			return errors.Wrap(ErrMountSourceNotAllowed, "sandbox: 挂载源为空或为根目录", "source", m.Source)
		}
		if isControlSocket(src) {
			return errors.Wrap(ErrMountSourceNotAllowed, "sandbox: 控制面 socket 一律拒绝（白名单不能放行）",
				"source", src)
		}
		if !sourceAllowed(src, p.MountSourceAllow) {
			return errors.Wrap(ErrMountSourceNotAllowed, "sandbox: 挂载源不在白名单",
				"source", src)
		}
		target := path.Clean(m.Target)
		if target == "" || target == "." {
			return errors.Wrap(ErrMountTargetNotAllowed, "sandbox: 挂载目标为空", "target", m.Target)
		}
		if len(p.MountTargetAllow) > 0 && !targetAllowed(target, p.MountTargetAllow) {
			return errors.Wrap(ErrMountTargetNotAllowed, "sandbox: 挂载目标不在白名单",
				"target", target)
		}
		if p.MountReadOnlyOnly && !m.ReadOnly {
			return errors.Wrap(ErrMountNotReadOnly, "sandbox: 策略要求只读挂载",
				"source", src, "target", target)
		}
	}
	return nil
}

// judgeCaps 判要求的 capability 是否都在声明的丢弃集合里。
func (p ExecPolicy) judgeCaps(dropped []string) error {
	if len(p.CapDrop) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(dropped))
	for _, c := range dropped {
		set[strings.ToUpper(c)] = struct{}{}
	}
	// ALL 覆盖一切：声明丢了 ALL 即满足任何逐项要求。
	if _, all := set["ALL"]; all {
		return nil
	}
	for _, want := range p.CapDrop {
		if _, ok := set[strings.ToUpper(want)]; !ok {
			return errors.Wrap(ErrCapNotDropped, "sandbox: 要求的 capability 未在声明中丢弃",
				"want", want)
		}
	}
	return nil
}

// judgeLimits 判资源上限：每个非零策略项都要求声明侧 > 0 且 <= 策略值。
//
// 两侧都为 0 的项不参与判定（该项不要求、也未声明——不假装兜住了）。
func (p ExecPolicy) judgeLimits(l Budget) error {
	type item struct {
		name    string
		want    int64
		got     int64
		require bool
	}
	// WallClock / MaxMemory 以纳秒与字节计，统一折成 int64 比较。
	items := []item{
		{"WallClock", int64(p.Limits.WallClock), int64(l.WallClock), p.Limits.WallClock > 0},
		{"MaxCalls", int64(p.Limits.MaxCalls), int64(l.MaxCalls), p.Limits.MaxCalls > 0},
		{"MaxBytes", int64(p.Limits.MaxBytes), int64(l.MaxBytes), p.Limits.MaxBytes > 0},
		{"MaxMemory", p.Limits.MaxMemory, l.MaxMemory, p.Limits.MaxMemory > 0},
	}
	for _, it := range items {
		if !it.require {
			continue
		}
		if it.got == 0 {
			return errors.Wrap(ErrLimitsExceeded, "sandbox: 策略要求该资源上限，声明未给出",
				"limit", it.name, "policy", it.want)
		}
		if it.got > it.want {
			return errors.Wrap(ErrLimitsExceeded, "sandbox: 声明的资源上限超出策略",
				"limit", it.name, "policy", it.want, "declared", it.got)
		}
	}
	return nil
}

// splitDigest 拆出 name@sha256:<64 hex> 里的 digest；不合法返回 false。
func splitDigest(image string) (string, bool) {
	i := strings.LastIndex(image, "@")
	if i < 0 || i == len(image)-1 {
		return "", false
	}
	digest := image[i+1:]
	if !strings.HasPrefix(strings.ToLower(digest), "sha256:") {
		return "", false
	}
	hex := digest[len("sha256:"):]
	if len(hex) != 64 {
		return "", false
	}
	for _, c := range hex {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return "", false
		}
	}
	return "sha256:" + strings.ToLower(hex), true
}

// normalizeDigest 把白名单条目归一到 "sha256:<hex>"（裸 hex 按 sha256 处理）。
func normalizeDigest(s string) string {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, ":") && len(s) == 64 {
		return "sha256:" + strings.ToLower(s)
	}
	return s
}

// foldSlash 把 Clean 后路径的两种分隔符形态统一为 slash 形态（#198）：
// Windows 的 Clean 会把清单里的 unix 字面量（/var/run/docker.sock）转成
// 反斜杠形态（\var\run\docker.sock），而 unix 上 Clean/ToSlash 都不动
// 字面反斜杠——单靠 ToSlash 在 unix 测试环境永远对不上。显式折叠让判定
// 在两个平台都可复现（CI 无 Windows runner 也能钉住本判据）。
func foldSlash(p string) string {
	return strings.ReplaceAll(filepath.ToSlash(filepath.Clean(p)), `\`, `/`)
}

// isControlSocket 判路径是否落在控制面 socket 上（或其变体，如 .raw 后缀）。
// 两侧（判定入参与清单字面量）都过 foldSlash 归一后再比较（#198）。
func isControlSocket(p string) bool {
	norm := foldSlash(p)
	for _, sock := range controlSockets {
		if norm == foldSlash(sock) || strings.HasPrefix(norm, foldSlash(sock)) {
			return true
		}
	}
	return false
}

// sourceAllowed 挂载源精确匹配白名单（Clean 后比较）。
func sourceAllowed(src string, allow []string) bool {
	for _, a := range allow {
		if filepath.Clean(a) == src {
			return true
		}
	}
	return false
}

// targetAllowed 挂载目标按前缀匹配白名单（Clean 后比较；/data 覆盖 /data/x）。
func targetAllowed(target string, allow []string) bool {
	for _, a := range allow {
		clean := path.Clean(a)
		if target == clean || strings.HasPrefix(target, clean+"/") {
			return true
		}
	}
	return false
}
