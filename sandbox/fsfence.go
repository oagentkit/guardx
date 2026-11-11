package sandbox

import (
	"os"
	"path/filepath"
	"strings"

	"fmt"

	"github.com/oekit/pkg/errors"
	"github.com/oekit/pkg/pathx"
)

// 围栏判定的两类失败（哨兵错误，调用方按需分派处置——比如 permgate 的
// 执行器装配把「越出围栏」映射为 deny，把「路径不合法」映射为参数错误）：
//
//   - ErrFenceOutside：路径**解析之后**落在 root 外——这是围栏的拦截结论；
//   - ErrFenceInvalid：路径**判不了**（显式 ".." 段 / 严格档不过 / 悬空
//     符号链接 / 空路径）——安全档宁可拒绝，也不做文本层推断。
var (
	ErrFenceOutside = errors.New("sandbox: 路径越出围栏 root")
	ErrFenceInvalid = errors.New("sandbox: 路径不合法（围栏拒判）")
)

// FSFence 文件系统围栏：判定「路径落在哪里」——root 内包含 + 符号链接落地
// + cwd 语义。与进程沙箱编排（Level / Provider / Registry）并列，是 sandbox
// 家族里**路径域**的成员。
//
// # 为什么要有这个原语
//
// 「路径必须落在指定 root 内」是外部 agent / 工具执行器的通用需求，但它
// **每一处都是坑**（下游手搓实现的实证清单，guardx#117）：
//
//  1. 文本层 `..` 抵消与符号链接的交互——filepath.Join 会把 "a/../b" 在
//     文本上抵消，而抵消是纯文本语义、看不见符号链接（"a" 若是软链，真实
//     落点可能落在根外）⇒ 显式 ".." 段一律拒绝，抵消根本没有机会发生；
//  2. EvalSymlinks 对**不存在目标**失败——写新文件是常态，降级路径是
//     「解析已存在的最深祖先 + 按文本拼回尾段」，且尾段里的**悬空符号链接**
//     必须拒判（文本拼接对符号链接等于未判定）；
//  3. root 自身在软链下的归一——macOS 的 /var 实为 /private/var，root 不
//     归一则与解析后路径的比较全部误判（构造期 EvalSymlinks 一次）；
//  4. cwd 语义——空 = 默认 root、相对 cwd 拼 root、落地后照样判包含；
//  5. 判定时机——包含关系必须在 EvalSymlinks **之后**判（先判就是拿
//     文本形态骗过围栏）。
//
// 本类型把这五处收成一份单源：执行器不再各自手搓，permgate 文档里
// 「符号链接围栏归执行器」的承诺有了落点。
//
// # 与 permgate 的分工
//
// permgate 判「要不要放行」——纯函数，不做文件系统访问（其路径 subject
// 匹配只做 Clean，符号链接围栏明确归执行器）；FSFence 判「路径落在哪里」
// ——真读文件系统（EvalSymlinks / Lstat）。两者是不同执行点上的互补原语：
// 许可判定过了，落地位置仍要过围栏；围栏不回答「该不该执行」，只回答
// 「落在哪里、是否越界」。
//
// # 判定契约（三层，顺序固定）
//
//  1. **文本层严格档**：相对路径先过 pathx.SanitizeRelStrict——显式 ".."
//     段、绝对形态、Windows 盘符、清洗后为空（"." / "a/.."）一律拒绝。
//     "/" 与 "\\" 都按分隔符（外部载荷口径，与 pathx 一致）；
//  2. **符号链接落地**：拼 root 后 EvalSymlinks 逐组件解析；目标不存在时
//     解析已存在的最深祖先、按文本拼回尾段（尾段组件逐个 Lstat，符号链接
//     一律拒判）；**包含关系在解析之后判**——解析后的真实路径不在
//     （归一后的）root 内即拒（ErrFenceOutside）；
//  3. **cwd 语义**：ResolveCwd 空（与 "."）回退 root，其余同 Resolve。
//
// # 已知边界（诚实声明）
//
//   - **TOCTOU 残窗**：本类型判定的是**调用时刻**的文件系统形态；判定与
//     实际读写之间路径仍可能被替换。缓解与 egress#60 同思路：**用返回的
//     落地路径**做实际操作（不要拿原输入重新拼一遍——那等于把判定丢掉）；
//     更强的闭合（O_NOFOLLOW / openat2）是执行器 syscall 层的事，本原语
//     不假装能做；
//   - **挂载点不可见**：bind mount / NFS 导出的路径在 EvalSymlinks 眼里
//     就是普通目录——文件系统围栏看不见挂载拓扑，那是容器/沙箱运行时
//     （Provider 实现）的职责；
//   - **大小写不敏感文件系统**（macOS 默认）：解析后比较按字节进行，
//     大小写变体不构成越界——root 内外的判定以**解析后真实形态**为准，
//     这正是先 EvalSymlinks 再判包含的原因。
//
// 并发安全：FSFence 构造后只读，可并发共享。
type FSFence struct {
	root string // EvalSymlinks 归一后的绝对路径（构造期定死）
}

// NewFSFence 构造围栏。root 必须**已存在**的绝对路径目录——构造期 fail-fast：
// root 不存在/不可达的围栏等于没围栏，带着它跑只会把越界发现推迟到执行期。
// root 经 EvalSymlinks 归一（macOS /var → /private/var 一类），此后一切
// 包含判定都在归一形态上进行。
func NewFSFence(root string) (*FSFence, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("sandbox: FSFence root 为空")
	}
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("sandbox: FSFence root 必须是绝对路径，实得 %q", root)
	}
	real, err := filepath.EvalSymlinks(filepath.Clean(root))
	if err != nil {
		return nil, errors.Wrap(err, "sandbox: FSFence root 不存在或不可达（构造期 fail-fast）", "root", root)
	}
	fi, err := os.Stat(real)
	if err != nil {
		return nil, errors.Wrap(err, "sandbox: FSFence root 不可读", "root", real)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("sandbox: FSFence root 不是目录: %s", real)
	}
	return &FSFence{root: real}, nil
}

// Root 返回归一后的围栏根（EvalSymlinks 之后的真实形态）。调用方需要把
// root 当 cwd / 展示给用户时用它，不要自己再 EvalSymlinks 一遍——那是
// 第二份归一逻辑，必然漂移。
func (f *FSFence) Root() string {
	return f.root
}

// Resolve 解析 path 并校验其落地在围栏内，返回**落地路径**（符号链接已
// 解析的真实形态）——调用方对文件系统的实际操作应当使用这个返回值，而不是
// 拿原输入重新拼（见类型文档的 TOCTOU 边界）。
//
// 相对路径按「root 下的仓库相对路径」处理（严格档）；绝对路径允许，但
// 落地（解析后）必须在 root 内。两类输入对显式 ".." 段同规：一律拒绝
// （ErrFenceInvalid）——文本抵消看不见符号链接，安全档不做这层推断，
// 目录回退语义请由调用方在业务层显式处理。
//
// 空路径与清洗后为空的形态（"." / "a/.."）按严格档拒绝：它们指向 root
// 本身而非具体条目——要根目录请用 Root() 或 ResolveCwd("")。
func (f *FSFence) Resolve(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.Wrap(ErrFenceInvalid, "sandbox: 空路径")
	}
	if filepath.IsAbs(path) {
		if hasExplicitDotDot(path) {
			return "", errors.Wrap(ErrFenceInvalid, "sandbox: 显式 \"..\" 段（文本抵消看不见符号链接，一律拒绝）: "+path)
		}
		return f.resolveFS(filepath.Clean(path))
	}
	cleaned, ok := pathx.SanitizeRelStrict(path)
	if !ok {
		return "", errors.Wrap(ErrFenceInvalid, "sandbox: 相对路径未过严格档（显式 \"..\"/绝对形态/盘符/清洗后为空一律拒绝）: "+path)
	}
	return f.resolveFS(filepath.Join(f.root, filepath.FromSlash(cleaned)))
}

// ResolveCwd 解析工作目录（cwd 语义）：空与 "." 回退 root；相对 cwd 按
// 「root 下相对路径」解析；绝对 cwd 落地后必须仍在 root 内——子进程的
// 工作目录是路径围栏的一部分，cwd 落在 root 外等于围栏从第一步就破了。
// 返回值同样是**落地路径**，起进程时用它。
func (f *FSFence) ResolveCwd(cwd string) (string, error) {
	if cwd == "" || cwd == "." {
		return f.root, nil
	}
	return f.Resolve(cwd)
}

// resolveFS 符号链接落地 + 包含判定（判定时机在解析之后——坑 5）。
func (f *FSFence) resolveFS(abs string) (string, error) {
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		// 目标不存在（写新文件是常态）/ 悬空符号链接 / 中途权限失败：
		// 解析已存在的最深祖先，其余尾段按文本拼回（坑 2 的降级路径）。
		real, err = f.resolveDegrade(abs)
		if err != nil {
			return "", err
		}
	}
	if !f.contains(real) {
		return "", errors.Wrap(ErrFenceOutside, "sandbox: 落地路径越出围栏", "resolved", real)
	}
	return real, nil
}

// resolveDegrade 自底向上找「已存在且可解析」的最深祖先，其余尾段按文本
// 拼回。尾段组件逐个 Lstat：凡是符号链接一律拒判——组件存在但整体解析
// 失败，意味着它是悬空软链（指向尚不存在的目标）或不可解析（权限）；文本
// 拼接对它等于未判定，而未来它的解析结果不受本围栏管。
func (f *FSFence) resolveDegrade(abs string) (string, error) {
	dir, tail := abs, ""
	for {
		real, err := filepath.EvalSymlinks(dir)
		if err == nil {
			cur := real
			for _, seg := range strings.Split(filepath.ToSlash(tail), "/") {
				if seg == "" {
					continue
				}
				cur = filepath.Join(cur, seg)
				if fi, lerr := os.Lstat(cur); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
					return "", errors.Wrap(ErrFenceInvalid, "sandbox: 路径尾段含符号链接（悬空/不可解析，拒判）: "+cur)
				}
			}
			return filepath.Join(real, filepath.FromSlash(tail)), nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.Wrap(ErrFenceInvalid, "sandbox: 路径到卷根仍无法解析: "+abs)
		}
		tail = filepath.Join(filepath.Base(dir), tail)
		dir = parent
	}
}

// contains 包含判定：解析后路径等于 root，或位于 root/<sep> 之下。
// root 与 resolved 都是归一形态（坑 3 在构造期解决）。
func (f *FSFence) contains(resolved string) bool {
	if resolved == f.root {
		return true
	}
	sep := string(filepath.Separator)
	if f.root == sep { // root 为 "/"：一切绝对路径都在内
		return filepath.IsAbs(resolved)
	}
	return strings.HasPrefix(resolved, f.root+sep)
}

// hasExplicitDotDot 输入里是否含显式 ".." 段（"/" 与 "\\" 都算分隔符，
// 与 pathx 的外部载荷口径一致）。相对与绝对同规。
func hasExplicitDotDot(path string) bool {
	for _, seg := range strings.FieldsFunc(path, func(r rune) bool {
		return r == '/' || r == '\\'
	}) {
		if seg == ".." {
			return true
		}
	}
	return false
}
