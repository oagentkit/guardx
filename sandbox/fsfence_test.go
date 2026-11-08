package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// 本文件钉 guardx#117 的回归：文件系统围栏原语（FSFence）——root containment
// + 符号链接落地 + cwd 语义。此前「归执行器」三处有言、无人实现，下游各自
// 手搓 106 行坑清单（文本抵消×符号链接 / EvalSymlinks 降级 / macOS /var 归一 /
// cwd 语义 / 判定时机）。以下用例按坑逐条钉。

// newTestFence 用 t.TempDir() 建围栏。macOS 的 TempDir 在 /var 下（软链）——
// 构造期归一（坑 3）被真实 exercised：Root() 必须是 EvalSymlinks 后的形态。
func newTestFence(t *testing.T) *FSFence {
	t.Helper()
	f, err := NewFSFence(t.TempDir())
	if err != nil {
		t.Fatalf("构造围栏失败: %v", err)
	}
	if !filepath.IsAbs(f.Root()) {
		t.Fatalf("Root() 必须是绝对路径，实得 %q", f.Root())
	}
	return f
}

// TestNewFSFenceNormalizesSymlinkedRoot 坑 3：root 自身在软链下（macOS /var
// → /private/var）必须归一，否则与解析后路径的比较全部误判。
func TestNewFSFenceNormalizesSymlinkedRoot(t *testing.T) {
	tmp := t.TempDir()
	f, err := NewFSFence(tmp)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	real, err := filepath.EvalSymlinks(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if f.Root() != real {
		t.Fatalf("Root() 应为归一形态 %q，实得 %q", real, f.Root())
	}
}

// TestNewFSFenceFailFast 构造期 fail-fast：root 不存在 / 是文件 / 相对路径
// / 空串——带着坏 root 跑只会把越界发现推迟到执行期。
func TestNewFSFenceFailFast(t *testing.T) {
	if _, err := NewFSFence(""); err == nil {
		t.Fatal("空 root 必须报错")
	}
	if _, err := NewFSFence("relative/path"); err == nil {
		t.Fatal("相对路径 root 必须报错")
	}
	if _, err := NewFSFence(filepath.Join(t.TempDir(), "不存在")); err == nil {
		t.Fatal("不存在的 root 必须报错（fail-fast）")
	}
	file := filepath.Join(t.TempDir(), "f.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFSFence(file); err == nil {
		t.Fatal("非目录 root 必须报错")
	}
}

// TestResolveRelativeInside 相对路径落 root 内：返回解析后的落地路径。
func TestResolveRelativeInside(t *testing.T) {
	f := newTestFence(t)
	if err := os.MkdirAll(filepath.Join(f.Root(), "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := f.Resolve("sub/f.txt")
	if err != nil {
		t.Fatalf("root 内相对路径应放行: %v", err)
	}
	if want := filepath.Join(f.Root(), "sub", "f.txt"); got != want {
		t.Fatalf("落地路径 %q，想要 %q", got, want)
	}
}

// TestResolveNewFileDegrade 坑 2：写新文件（目标不存在）——解析已存在的
// 最深祖先、文本拼回尾段，落地仍判包含。
func TestResolveNewFileDegrade(t *testing.T) {
	f := newTestFence(t)
	got, err := f.Resolve(filepath.Join("newdir", "deeper", "new.txt"))
	if err != nil {
		t.Fatalf("写新文件场景应放行: %v", err)
	}
	if want := filepath.Join(f.Root(), "newdir", "deeper", "new.txt"); got != want {
		t.Fatalf("落地路径 %q，想要 %q", got, want)
	}
	// 落地路径真的可用来创建文件（这就是降级路径存在的意义）。
	if err := os.MkdirAll(filepath.Dir(got), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(got, []byte("x"), 0o644); err != nil {
		t.Fatalf("按落地路径创建文件失败: %v", err)
	}
}

// TestResolveExplicitDotDotRejected 坑 1：显式 ".." 段一律拒绝（相对与绝对
// 同规）——filepath.Join 的文本抵消看不见符号链接，安全档不做这层推断。
func TestResolveExplicitDotDotRejected(t *testing.T) {
	f := newTestFence(t)
	// 注意：绝对形态的用例必须按**原样字符串**构造——filepath.Join 会在
	// 测试构造期就把 "a/.." 文本抵消掉，用例就不再含 ".." 了。
	absDotDot := f.Root() + "/a/../b"
	for _, p := range []string{"a/../b", "../escape", "a/b/../../c", absDotDot} {
		if got, err := f.Resolve(p); err == nil {
			t.Fatalf("显式 .. 段必须拒绝（%q），实得 %q", p, got)
		} else if !errors.Is(err, ErrFenceInvalid) {
			t.Fatalf("%q 应报 ErrFenceInvalid，实得 %v", p, err)
		}
	}
}

// TestResolveStrictRejectedForms 严格档的拒绝形态（与 pathx.SanitizeRelStrict
// 同一口径）+ 空路径。绝对形态的拒绝（越出 root → ErrFenceOutside）在
// TestResolveAbsoluteInsideAndOutside 覆盖。
func TestResolveStrictRejectedForms(t *testing.T) {
	f := newTestFence(t)
	for _, p := range []string{"", ".", "a/..", "  "} {
		if _, err := f.Resolve(p); !errors.Is(err, ErrFenceInvalid) {
			t.Fatalf("%q 应报 ErrFenceInvalid，实得 %v", p, err)
		}
	}
	// "." 指向 root 本身、非具体条目——要根目录请走 ResolveCwd。
}

// TestResolveAbsoluteInsideAndOutside 绝对路径：落地（解析后）在 root 内放行、
// 在外拒绝——包含关系判的是解析后的真实形态。
func TestResolveAbsoluteInsideAndOutside(t *testing.T) {
	f := newTestFence(t)
	inside := filepath.Join(f.Root(), "abs.txt")
	if got, err := f.Resolve(inside); err != nil || got != inside {
		t.Fatalf("root 内绝对路径应放行，实得 %q, %v", got, err)
	}
	if _, err := f.Resolve("/etc/hosts"); !errors.Is(err, ErrFenceOutside) {
		t.Fatalf("root 外绝对路径应报 ErrFenceOutside，实得 %v", err)
	}
	if _, err := f.Resolve(t.TempDir()); err == nil {
		t.Fatal("另一个 TempDir（root 外）必须被拒")
	}
}

// TestResolveSymlinkLanding 坑 5：包含关系必须在 EvalSymlinks **之后**判——
// 指向 root 外的软链按真实落点拒，指向 root 内的软链按真实落点放。
func TestResolveSymlinkLanding(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows 建符号链接需要特权/开发者模式——本组语义在 unix 上覆盖（平台能力边界，诚实标注）")
	}
	f := newTestFence(t)
	outside := t.TempDir() // root 外的目录
	if err := os.MkdirAll(filepath.Join(f.Root(), "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	lnOut := filepath.Join(f.Root(), "ln-out")
	if err := os.Symlink(outside, lnOut); err != nil {
		t.Fatal(err)
	}
	lnIn := filepath.Join(f.Root(), "ln-in")
	if err := os.Symlink(filepath.Join(f.Root(), "sub"), lnIn); err != nil {
		t.Fatal(err)
	}
	// 软链指向 root 外：文本形态在 root 内（root/ln-out/file.txt），
	// 真实落点在 root 外 —— 必须按落地判、拒。
	if _, err := f.Resolve(filepath.Join("ln-out", "file.txt")); !errors.Is(err, ErrFenceOutside) {
		t.Fatalf("指向 root 外的软链必须按落地路径拒（坑 5），实得 %v", err)
	}
	// 软链指向 root 内：放行，返回解析后的真实落点。
	got, err := f.Resolve(filepath.Join("ln-in", "f.txt"))
	if err != nil {
		t.Fatalf("指向 root 内的软链应放行: %v", err)
	}
	if want := filepath.Join(f.Root(), "sub", "f.txt"); got != want {
		t.Fatalf("落地路径 %q，想要 %q", got, want)
	}
}

// TestResolveDanglingSymlinkRejected 尾段里的悬空软链必须拒判：文本拼接对
// 符号链接等于未判定，而它未来的解析结果不受本围栏管。
func TestResolveDanglingSymlinkRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows 建符号链接需要特权/开发者模式——本组语义在 unix 上覆盖（平台能力边界，诚实标注）")
	}
	f := newTestFence(t)
	dangling := filepath.Join(f.Root(), "dangling")
	if err := os.Symlink(filepath.Join(f.Root(), "nowhere"), dangling); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Resolve(filepath.Join("dangling", "x.txt")); !errors.Is(err, ErrFenceInvalid) {
		t.Fatalf("悬空软链应报 ErrFenceInvalid，实得 %v", err)
	}
}

// TestResolveCwdSemantics 坑 4：cwd 语义——空与 "." 回退 root；相对 cwd 拼
// root；绝对 cwd 落地后判包含；".." 拒。
func TestResolveCwdSemantics(t *testing.T) {
	f := newTestFence(t)
	if got, err := f.ResolveCwd(""); err != nil || got != f.Root() {
		t.Fatalf("空 cwd 应回退 root，实得 %q, %v", got, err)
	}
	if got, err := f.ResolveCwd("."); err != nil || got != f.Root() {
		t.Fatalf("\".\" cwd 应回退 root，实得 %q, %v", got, err)
	}
	if err := os.MkdirAll(filepath.Join(f.Root(), "work"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := f.ResolveCwd("work"); err != nil || got != filepath.Join(f.Root(), "work") {
		t.Fatalf("相对 cwd 应落 root/work，实得 %q, %v", got, err)
	}
	if got, err := f.ResolveCwd(f.Root()); err != nil || got != f.Root() {
		t.Fatalf("root 本身作为绝对 cwd 应放行，实得 %q, %v", got, err)
	}
	if _, err := f.ResolveCwd(t.TempDir()); !errors.Is(err, ErrFenceOutside) {
		t.Fatalf("root 外的绝对 cwd 应拒，实得 %v", err)
	}
	if _, err := f.ResolveCwd("../escape"); !errors.Is(err, ErrFenceInvalid) {
		t.Fatalf("越 root 的相对 cwd 应报 ErrFenceInvalid，实得 %v", err)
	}
}

// TestResolveBackslashAsSeparator pathx 口径：外部载荷里 "\\" 同样按分隔符
// （Linux 上按平台解释会让 "a\\..\\..\\x" 形态漏掉）。
func TestResolveBackslashAsSeparator(t *testing.T) {
	f := newTestFence(t)
	if _, err := f.Resolve(`sub\..\..\escape`); !errors.Is(err, ErrFenceInvalid) {
		t.Fatalf("反斜杠分隔的显式 .. 应被拒，实得 %v", err)
	}
	got, err := f.Resolve(`sub\f.txt`)
	if err != nil {
		t.Fatalf("反斜杠分隔的相对路径应放行: %v", err)
	}
	if want := filepath.Join(f.Root(), "sub", "f.txt"); got != want {
		t.Fatalf("落地路径 %q，想要 %q", got, want)
	}
}
