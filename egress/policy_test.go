package egress

import (
	"errors"
	"testing"
)

func TestPolicyNamedSurfaces(t *testing.T) {
	cases := []struct {
		name  string
		p     Policy
		host  string
		allow bool
	}{
		{"公网", PublicOnly, "93.184.216.34", true},
		{"私网", PublicOnly, "10.44.1.5", false},
		{"回环", PublicOnly, "127.0.0.1", false},
		{"云元数据", PublicOnly, "169.254.169.254", false},
		{"CGNAT", PublicOnly, "100.64.0.1", false},
		{"私网放行-私网", PrivateNoLoopback, "10.44.1.5", true},
		{"私网放行-ULA", PrivateNoLoopback, "fd00::8", true},
		{"私网放行-回环仍拒", PrivateNoLoopback, "127.0.0.1", false},
		{"私网放行-元数据仍拒", PrivateNoLoopback, "169.254.169.254", false},
		{"自服务-私网", SelfService, "10.44.1.5", true},
		{"自服务-回环", SelfService, "127.0.0.1", true},
		{"自服务-元数据仍拒", SelfService, "169.254.169.254", false},
	}
	for _, c := range cases {
		err := c.p.CheckHost(c.host)
		if c.allow {
			if err != nil {
				t.Fatalf("%s：%s 应放行：%v", c.name, c.host, err)
			}
			continue
		}
		if err == nil {
			t.Fatalf("%s：%s 应被拒", c.name, c.host)
		}
		var blocked *BlockedError
		if !errors.As(err, &blocked) {
			t.Fatalf("%s：%s 的拒绝原因应是 *BlockedError，实际 %T", c.name, c.host, err)
		}
	}
}

func TestPolicyWriteSideParity(t *testing.T) {
	pols := []struct {
		name string
		p    Policy
	}{
		{"PublicOnly", PublicOnly},
		{"PrivateNoLoopback", PrivateNoLoopback},
		{"SelfService", SelfService},
	}
	urls := []string{
		"http://example.com/",
		"http://10.44.1.5/x",
		"http://127.0.0.1:8080/x",
		"http://[::1]:8080/x",
		"http://169.254.169.254/latest/meta-data",
	}
	for _, pol := range pols {
		for _, u := range urls {
			got := pol.p.Check(u)
			want := CheckWith(u, pol.p)
			if (got == nil) != (want == nil) {
				t.Fatalf("%s：Policy.Check 与 CheckWith 对 %s 的结论不一致（%v vs %v）",
					pol.name, u, got, want)
			}
			if got != nil && want != nil && got.Error() != want.Error() {
				t.Fatalf("%s：Policy.Check 与 CheckWith 对 %s 的拒绝原因不一致（%q vs %q）",
					pol.name, u, got.Error(), want.Error())
			}
		}
	}
}

func TestPolicyZeroValueIsPublicOnly(t *testing.T) {
	var p Policy
	if p != PublicOnly {
		t.Fatalf("零值 Policy 应等价于 PublicOnly，实际 %#v", p)
	}
	// 与 Check / CheckHost 的缺省口径一致
	if err := p.CheckHost("10.44.1.5"); err == nil {
		t.Fatal("零值应拒私网")
	}
	if err := p.CheckHost("93.184.216.34"); err != nil {
		t.Fatalf("零值应放公网：%v", err)
	}
	if err := p.Check("http://example.com/"); err != nil {
		t.Fatalf("零值应放域名：%v", err)
	}
}

// sameType 编译期证明两个值是**同一个类型**（两个具名类型之间不可赋值——
// 所以 Options 只有在与 Policy 是别名时才传得进来）。
func sameType[T any](a, b T) {}

func TestOptionsAliasCompatibility(t *testing.T) {
	// 旧名照旧可用，且与 Policy 是**同一个类型**（不是两套并行表示）
	o := Options{AllowPrivate: true}
	sameType[Policy](o, PrivateNoLoopback)
	p := Policy(o)
	if p != PrivateNoLoopback {
		t.Fatalf("Options{AllowPrivate: true} 应等价于 PrivateNoLoopback，实际 %#v", p)
	}
	// 旧调用点（CheckWith 收 Options）照旧工作
	if err := CheckWith("http://10.44.1.5/x", o); err != nil {
		t.Fatalf("旧调用点应放行私网：%v", err)
	}
	if err := CheckWith("http://127.0.0.1/x", o); err == nil {
		t.Fatal("旧调用点应拒回环")
	}
}
