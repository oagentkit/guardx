package sandbox

import (
	"strings"
	"testing"
	"time"

	"github.com/oekit/pkg/errors"
)

const (
	testDigestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testDigestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// 验收主线：白名单 + 只读 + digest 通过。
func TestExecPolicyJudgeAcceptsAllowedSpec(t *testing.T) {
	p := ExecPolicy{
		ImageDigestAllow:  []string{testDigestA},
		MountSourceAllow:  []string{"/srv/app-data"},
		MountTargetAllow:  []string{"/app/data"},
		MountReadOnlyOnly: true,
		ReadOnlyRootfs:    true,
		RequireNonRoot:    true,
		CapDrop:           []string{"ALL"},
		SeccompProfile:    "runtime/default",
		Limits:            Budget{WallClock: time.Minute, MaxMemory: 256 << 20},
	}
	s := Spec{
		Image:          "registry.example/app@" + testDigestA,
		Mounts:         []Mount{{Source: "/srv/app-data", Target: "/app/data", ReadOnly: true}},
		RootfsReadOnly: true,
		NonRoot:        true,
		CapDrop:        []string{"ALL"},
		SeccompProfile: "Runtime/Default", // 大小写不敏感
		Limits:         Budget{WallClock: 30 * time.Second, MaxMemory: 128 << 20},
	}
	if err := p.Judge(s); err != nil {
		t.Fatalf("合规声明被拒: %v", err)
	}
}

// 验收：挂 docker.sock / /etc / 非白名单源 / tag 镜像 / 非只读挂载 ⇒ 逐条被拒。
func TestExecPolicyJudgeRejectsEachViolation(t *testing.T) {
	p := ExecPolicy{
		ImageDigestAllow:  []string{testDigestA},
		MountSourceAllow:  []string{"/srv/app-data"},
		MountReadOnlyOnly: true,
	}
	base := func() Spec {
		return Spec{
			Image:  "registry.example/app@" + testDigestA,
			Mounts: []Mount{{Source: "/srv/app-data", Target: "/app/data", ReadOnly: true}},
		}
	}
	cases := []struct {
		name   string
		mutate func(*Spec)
		want   error
	}{
		{"tag 镜像", func(s *Spec) { s.Image = "registry.example/app:latest" }, ErrImageNotPinned},
		{"digest 不在白名单", func(s *Spec) { s.Image = "registry.example/app@" + testDigestB }, ErrImageDigestNotAllowed},
		{"挂 docker.sock", func(s *Spec) {
			s.Mounts = []Mount{{Source: "/var/run/docker.sock", Target: "/var/run/docker.sock", ReadOnly: true}}
		}, ErrMountSourceNotAllowed},
		{"挂 /etc", func(s *Spec) {
			s.Mounts = []Mount{{Source: "/etc", Target: "/etc", ReadOnly: true}}
		}, ErrMountSourceNotAllowed},
		{"非白名单源", func(s *Spec) {
			s.Mounts = []Mount{{Source: "/home/user/.ssh", Target: "/keys", ReadOnly: true}}
		}, ErrMountSourceNotAllowed},
		{"非只读挂载", func(s *Spec) { s.Mounts[0].ReadOnly = false }, ErrMountNotReadOnly},
		{"源为根目录", func(s *Spec) {
			s.Mounts = []Mount{{Source: "/", Target: "/host", ReadOnly: true}}
		}, ErrMountSourceNotAllowed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := base()
			c.mutate(&s)
			err := p.Judge(s)
			if err == nil {
				t.Fatalf("%s: 期望被拒，实际通过", c.name)
			}
			if !errors.Is(err, c.want) {
				t.Fatalf("%s: 期望哨兵 %v，实际 %v", c.name, c.want, err)
			}
		})
	}
}

// 控制面 socket 即使写进白名单也必须拒（白名单只能收紧不能放宽）。
func TestExecPolicyControlSocketAlwaysDenied(t *testing.T) {
	p := ExecPolicy{
		MountSourceAllow: []string{"/var/run/docker.sock", "/run/containerd/containerd.sock"},
	}
	for _, src := range []string{"/var/run/docker.sock", "/run/containerd/containerd.sock", "/var/run/docker.sock.raw"} {
		err := p.Judge(Spec{Image: "app@" + testDigestA, Mounts: []Mount{{Source: src, Target: "/sock", ReadOnly: true}}})
		if !errors.Is(err, ErrMountSourceNotAllowed) {
			t.Fatalf("%s: 控制面 socket 未被拒: %v", src, err)
		}
	}
}

// 零值策略 fail-closed：镜像仍须 digest，挂载全拒。
func TestExecPolicyZeroValueIsStrict(t *testing.T) {
	var p ExecPolicy
	if err := p.Judge(Spec{Image: "app:latest"}); !errors.Is(err, ErrImageNotPinned) {
		t.Fatalf("零值策略应要求 digest: %v", err)
	}
	if err := p.Judge(Spec{Image: "app@" + testDigestA}); err != nil {
		t.Fatalf("零值策略 + digest 且无挂载应通过: %v", err)
	}
	if err := p.Judge(Spec{
		Image:  "app@" + testDigestA,
		Mounts: []Mount{{Source: "/data", Target: "/data", ReadOnly: true}},
	}); !errors.Is(err, ErrMountSourceNotAllowed) {
		t.Fatalf("零值策略应拒绝任何挂载: %v", err)
	}
}

// 布尔要求项：rootfs 只读 / 非 root。
func TestExecPolicyBooleanRequirements(t *testing.T) {
	p := ExecPolicy{ReadOnlyRootfs: true}
	if err := p.Judge(Spec{Image: "app@" + testDigestA}); !errors.Is(err, ErrRootfsNotReadOnly) {
		t.Fatalf("rootfs 要求未生效: %v", err)
	}
	p = ExecPolicy{RequireNonRoot: true}
	if err := p.Judge(Spec{Image: "app@" + testDigestA}); !errors.Is(err, ErrRequireNonRoot) {
		t.Fatalf("非 root 要求未生效: %v", err)
	}
}

// caps / seccomp / 资源上限。
func TestExecPolicyCapsSeccompLimits(t *testing.T) {
	p := ExecPolicy{
		CapDrop:        []string{"ALL", "net_raw"},
		SeccompProfile: "runtime/default",
		Limits:         Budget{WallClock: time.Minute, MaxMemory: 256 << 20, MaxBytes: 4096},
	}
	// ALL 覆盖逐项要求。
	if err := p.Judge(Spec{Image: "app@" + testDigestA, CapDrop: []string{"all"}, SeccompProfile: "runtime/default",
		Limits: Budget{WallClock: time.Second, MaxMemory: 1, MaxBytes: 1}}); err != nil {
		t.Fatalf("ALL + 合规 limits 应通过: %v", err)
	}
	// 未丢要求的 cap。
	if err := p.Judge(Spec{Image: "app@" + testDigestA, CapDrop: []string{"net_raw"}, SeccompProfile: "runtime/default"}); !errors.Is(err, ErrCapNotDropped) {
		t.Fatalf("缺 ALL 时应拒: %v", err)
	}
	// seccomp 不符。
	if err := p.Judge(Spec{Image: "app@" + testDigestA, CapDrop: []string{"ALL"}, SeccompProfile: "unconfined"}); !errors.Is(err, ErrSeccompNotAllowed) {
		t.Fatalf("seccomp 不符应拒: %v", err)
	}
	// 未声明策略要求的限制。
	if err := p.Judge(Spec{Image: "app@" + testDigestA, CapDrop: []string{"ALL"}, SeccompProfile: "runtime/default"}); !errors.Is(err, ErrLimitsExceeded) {
		t.Fatalf("缺 limits 应拒: %v", err)
	}
	// 超出策略上限。
	if err := p.Judge(Spec{Image: "app@" + testDigestA, CapDrop: []string{"ALL"}, SeccompProfile: "runtime/default",
		Limits: Budget{WallClock: 2 * time.Minute, MaxMemory: 1, MaxBytes: 1}}); !errors.Is(err, ErrLimitsExceeded) {
		t.Fatalf("超限应拒: %v", err)
	}
}

// 挂载目标白名单前缀匹配。
func TestExecPolicyMountTargetPrefix(t *testing.T) {
	p := ExecPolicy{
		MountSourceAllow: []string{"/srv/data"},
		MountTargetAllow: []string{"/app/data"},
	}
	ok := Spec{Image: "app@" + testDigestA, Mounts: []Mount{{Source: "/srv/data", Target: "/app/data/sub"}}}
	if err := p.Judge(ok); err != nil {
		t.Fatalf("前缀匹配应通过: %v", err)
	}
	bad := Spec{Image: "app@" + testDigestA, Mounts: []Mount{{Source: "/srv/data", Target: "/etc"}}}
	if err := p.Judge(bad); !errors.Is(err, ErrMountTargetNotAllowed) {
		t.Fatalf("目标越界应拒: %v", err)
	}
}

// digest 归一：白名单裸 64 位 hex 按 sha256 处理。
func TestExecPolicyDigestNormalization(t *testing.T) {
	hex := strings.TrimPrefix(testDigestA, "sha256:")
	p := ExecPolicy{ImageDigestAllow: []string{hex}}
	if err := p.Judge(Spec{Image: "app@" + testDigestA}); err != nil {
		t.Fatalf("裸 hex 白名单应命中: %v", err)
	}
}

// 非法 digest 形态（长度/字符）一律按未钉住处理。
func TestExecPolicyInvalidDigestShapes(t *testing.T) {
	for _, img := range []string{
		"app@sha256:short",
		"app@md5:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"app@sha256:" + strings.Repeat("z", 64),
		"app@",
	} {
		err := (ExecPolicy{}).Judge(Spec{Image: img})
		if !errors.Is(err, ErrImageNotPinned) {
			t.Fatalf("%q 应判未钉住: %v", img, err)
		}
	}
}
