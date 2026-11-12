package logredact

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

func TestMaskerExactAndIPv4(t *testing.T) {
	m := NewMasker()
	tok := m.AddSecret("web-prod-01")
	if tok != "«T1»" {
		t.Fatalf("首个令牌应为 «T1»，得 %q", tok)
	}
	in := "host web-prod-01 (192.168.1.10) unreachable, retry 192.168.1.10"
	masked := m.Mask(in)
	if strings.Contains(masked, "web-prod-01") || strings.Contains(masked, "192.168.1.10") {
		t.Fatalf("掩码泄漏: %q", masked)
	}
	// 同 IP 恒同令牌（两处 IP 都应是 «T2»）
	if strings.Count(masked, "«T2»") != 2 {
		t.Fatalf("两处 IP 应同令牌 «T2»: %q", masked)
	}
	back := m.Restore(masked)
	if back != in {
		t.Fatalf("回填应无损:\n got %q\nwant %q", back, in)
	}
}

func TestMaskerUnknownTokenPreserved(t *testing.T) {
	m := NewMasker()
	in := "报告引用 «T99» 与 «T1x»"
	if got := m.Restore(in); got != in {
		t.Fatalf("未知令牌应原样保留: %q", got)
	}
}

func TestMaskerConcurrent(t *testing.T) {
	m := NewMasker()
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			m.AddSecret("host-" + string(rune('a'+i)))
			_ = m.Mask("10.0.0." + string(rune('1'+i)) + " down")
			_ = m.Restore("«T1» ok")
		})
	}
	wg.Wait()
}

// 结构化双视图（guardx#54）：MaskValue/UnmaskValue 键不动、逐字符串值替换——
// 替代 json.Marshal→Mask→Unmarshal 往返（其正确性依赖「令牌只在字符串值里」
// 与「替换不破坏 JSON 结构」两个未经类型化保证的假设，guardx#44 已实证同款
// 结构风险）。
func TestMaskerValueWalk(t *testing.T) {
	m := NewMasker()
	if tok := m.AddSecret("db.example.com"); tok == "" {
		t.Fatal("注册串应得令牌")
	}
	in := map[string]any{
		"host":    "10.1.2.3",
		"cluster": "db.example.com",
		"detail":  map[string]any{"peer": "10.1.2.4", "note": "see db.example.com"},
		"peers":   []any{"10.1.2.5", 42, true},
		"count":   7,
	}
	masked := m.MaskValue(in).(map[string]any)
	// 字符串值被掩码（IPv4 动态注册 + 精确串）
	if masked["host"] != "«T1»" && masked["host"] == "10.1.2.3" {
		t.Fatalf("IPv4 应被掩码: %v", masked["host"])
	}
	if !strings.Contains(masked["cluster"].(string), "«T") {
		t.Fatalf("注册串应被掩码: %v", masked["cluster"])
	}
	// 嵌套与数组内的字符串值同样处理
	detail := masked["detail"].(map[string]any)
	if strings.Contains(detail["peer"].(string), "10.1.2") {
		t.Fatalf("嵌套 IPv4 应被掩码: %v", detail["peer"])
	}
	if strings.Contains(detail["note"].(string), "db.example.com") {
		t.Fatalf("嵌套注册串应被掩码: %v", detail["note"])
	}
	peers := masked["peers"].([]any)
	if strings.Contains(peers[0].(string), "10.1.2") {
		t.Fatalf("数组内 IPv4 应被掩码: %v", peers[0])
	}
	// 非字符串标量原样、键不动
	if peers[1] != 42 || peers[2] != true || masked["count"] != 7 {
		t.Fatalf("非字符串标量应原样: %+v", masked)
	}
	if _, hasKey := masked["cluster"]; !hasKey {
		t.Fatal("键不得被动")
	}
	// 入参不被污染（输出为副本）
	if in["host"] != "10.1.2.3" {
		t.Fatalf("入参不得被掩码污染: %v", in["host"])
	}
	// 逆视图回填：结构与键不动，字符串值还原
	restored := m.UnmaskValue(masked).(map[string]any)
	if restored["host"] != "10.1.2.3" {
		t.Fatalf("IPv4 应回填: %v", restored["host"])
	}
	if restored["cluster"] != "db.example.com" {
		t.Fatalf("注册串应回填: %v", restored["cluster"])
	}
	rd := restored["detail"].(map[string]any)
	if rd["note"] != "see db.example.com" {
		t.Fatalf("嵌套注册串应回填: %v", rd["note"])
	}
	// JSON 往返兼容（结构化管线常用形态）：掩码→序列化→反序列化→回填
	b, _ := json.Marshal(masked)
	var round map[string]any
	_ = json.Unmarshal(b, &round)
	restored2 := m.UnmaskValue(round).(map[string]any)
	if restored2["host"] != "10.1.2.3" {
		t.Fatalf("JSON 往返后回填应成立: %v", restored2["host"])
	}
}
