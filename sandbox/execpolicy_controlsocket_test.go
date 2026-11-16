package sandbox

import (
	"testing"
)

// #198：控制面判据在 Windows 上曾整体空转——清单是 unix 字面量，判定前
// filepath.Clean 把 unix 形态转成反斜杠形态，单侧比较一条都命不中；且
// Windows 真实控制面（Docker Desktop 命名管族）不在清单里。修复=两侧
// ToSlash 归一 + 清单补命名管族。本文件全部用**字符串字面量**模拟
// Windows 形态，unix CI 上同样可判（ToSlash 在 unix 是恒等，反斜杠串
// 经归一后与清单同形）。

func TestIsControlSocketWindowsBackslashForm(t *testing.T) {
	// Windows Clean 后的形态：\var\run\docker.sock（反斜杠）。
	if !isControlSocket(`\var\run\docker.sock`) {
		t.Fatal("Windows 反斜杠形态的 docker.sock 应命中控制面清单（#198 修复前空转）")
	}
	if !isControlSocket(`\run\containerd\containerd.sock`) {
		t.Fatal("Windows 反斜杠形态的 containerd.sock 应命中")
	}
	// 变体后缀保持既有宽松前缀语义。
	if !isControlSocket(`\var\run\docker.sock.raw`) {
		t.Fatal("变体后缀应命中")
	}
	// 负例：非控制面路径不得误伤。
	if isControlSocket(`\var\run\data.sock`) {
		t.Fatal("非控制面路径不应命中")
	}
	if isControlSocket(`/var/run/data/`) {
		t.Fatal("非控制面前缀不应命中")
	}
}

func TestIsControlSocketNamedPipes(t *testing.T) {
	for _, pipe := range []string{
		`\\.\pipe\docker_engine`,
		`\\.\pipe\dockerDesktopLinuxEngine`,
		`\\.\pipe\dockerDesktopWindowsEngine`,
	} {
		if !isControlSocket(pipe) {
			t.Fatalf("命名管 %s 应命中控制面清单（#198 Windows 真实控制面）", pipe)
		}
	}
	// 负例：普通命名管不是容器控制面。
	if isControlSocket(`\\.\pipe\my_app_rpc`) {
		t.Fatal("非容器控制面的命名管不应命中")
	}
}

// Judge 层面回归：Windows 形态的挂载源必须被拒（修复前零覆盖）。
func TestJudgeWindowsControlSocketMount(t *testing.T) {
	policy := ExecPolicy{MountSourceAllow: []string{`/var/run/docker.sock`}}
	spec := Spec{
		Image:  "registry.example/app@sha256:0000000000000000000000000000000000000001",
		Mounts: []Mount{{Source: `\var\run\docker.sock`, Target: `/sock`, ReadOnly: true}},
	}
	if err := policy.Judge(spec); err == nil {
		t.Fatal("Windows 反斜杠形态的控制面挂载应被硬拒绝（白名单不能放行控制面）")
	}

	pipePolicy := ExecPolicy{} // 白名单为空：命名管族应无条件拒绝
	pipeSpec := Spec{
		Image:  "registry.example/app@sha256:0000000000000000000000000000000000000001",
		Mounts: []Mount{{Source: `\\.\pipe\docker_engine`, Target: `/pipe`, ReadOnly: true}},
	}
	if err := pipePolicy.Judge(pipeSpec); err == nil {
		t.Fatal("命名管控制面挂载应被硬拒绝")
	}
}
