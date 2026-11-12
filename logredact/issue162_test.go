package logredact

// 本文件钉 guardx#162 的回归：类型化复合形态（map/slice/array/struct/指针）
// 的凭证键必须整值清空——maskValueFor 此前对复合类型返回 false、调用方转
// 下探，而下探只过文本形状规则，形状认不出的凭证（随机口令、base64 私有
// token）原样落盘：同一份数据、同一个 api_key 键名，只因容器形态不同两种结局
// （any 形态打码、类型化形态泄漏），违「键表内的键，值必被打码」承诺。

import (
	"encoding/json"
	"strings"
	"testing"
)

// leakValue 刻意不匹配任何内置形状规则的凭证值（随机口令/base64 token 形态），
// 用来区分「键名整值打码」与「形状规则兜底」。
const leakValue = "ZXc3cmV0LXZhbHVlLW5vdC1tYXRjaC1hbnktc2hhcGU"

// TestCredentialKeyCompositeClear_Issue162 实验组：凭证键 × 复合元素/字段
// 类型 ⇒ 值被清空，原文一个字节不留。
func TestCredentialKeyCompositeClear_Issue162(t *testing.T) {
	// B1 map[string][]string
	b1, ok := RedactValue(map[string][]string{"api_key": {leakValue}}).(map[string][]string)
	if !ok {
		t.Fatalf("输出应保持 map[string][]string 形态")
	}
	if len(b1["api_key"]) != 0 || strings.Contains(strings.Join(b1["api_key"], ""), leakValue) {
		t.Fatalf("凭证键 []string 应被清空: %v", b1["api_key"])
	}

	// B2 map[string]map[string]string
	b2, ok := RedactValue(map[string]map[string]string{"api_key": {"k": leakValue}}).(map[string]map[string]string)
	if !ok {
		t.Fatalf("输出应保持 map[string]map[string]string 形态")
	}
	if len(b2["api_key"]) != 0 {
		t.Fatalf("凭证键 map 应被清空: %v", b2["api_key"])
	}

	// B3 map[string][]string 之外的 array 元素类型（长度保形、内容清零）
	b3, ok := RedactValue(map[string][1]string{"api_key": {leakValue}}).(map[string][1]string)
	if !ok {
		t.Fatalf("输出应保持 map[string][1]string 形态")
	}
	if b3["api_key"][0] != "" {
		t.Fatalf("凭证键 array 应清零: %v", b3["api_key"])
	}

	// C0 struct 切片字段
	type structSlice struct {
		APIKey []string `json:"api_key"`
		Note   string   `json:"note"`
	}
	c0, ok := RedactValue(structSlice{APIKey: []string{leakValue}, Note: "keep"}).(structSlice)
	if !ok {
		t.Fatalf("输出应保持 struct 形态")
	}
	if len(c0.APIKey) != 0 {
		t.Fatalf("struct 凭证键切片字段应被清空: %v", c0.APIKey)
	}
	if c0.Note != "keep" {
		t.Fatalf("非凭证字段不得动: %q", c0.Note)
	}

	// C1 struct map 字段
	type structMap struct {
		APIKey map[string]string `json:"api_key"`
	}
	c1, ok := RedactValue(structMap{APIKey: map[string]string{"k": leakValue}}).(structMap)
	if !ok {
		t.Fatalf("输出应保持 struct 形态")
	}
	if len(c1.APIKey) != 0 {
		t.Fatalf("struct 凭证键 map 字段应被清空: %v", c1.APIKey)
	}

	// C2 指针字段（fix 方向：pointer ⇒ nil）
	type structPtr struct {
		APIKey *string `json:"api_key"`
	}
	leak := leakValue
	c2, ok := RedactValue(structPtr{APIKey: &leak}).(structPtr)
	if !ok {
		t.Fatalf("输出应保持 struct 形态")
	}
	if c2.APIKey != nil {
		t.Fatalf("struct 凭证键指针字段应被清成 nil: %v", *c2.APIKey)
	}

	// D any 形态基线不回归（本来就打码）
	d, ok := RedactValue(map[string]any{"api_key": []any{leakValue}}).(map[string]any)
	if !ok {
		t.Fatalf("输出应保持 map[string]any 形态")
	}
	if d["api_key"] != "****" {
		t.Fatalf("any 形态凭证键应整值打码（基线）: %v", d["api_key"])
	}
}

// TestCredentialKeyCompositeNoFalseClear_Issue162 对照组：非凭证键的同形态
// 复合值必须保留（修复不得把正常载荷清掉）；数字/布尔凭证键保持原值。
func TestCredentialKeyCompositeNoFalseClear_Issue162(t *testing.T) {
	// 对照 C：非凭证键 + []string（不得清空）
	c, ok := RedactValue(map[string][]string{"note": {leakValue}}).(map[string][]string)
	if !ok {
		t.Fatalf("输出应保持 map[string][]string 形态")
	}
	if len(c["note"]) != 1 || c["note"][0] != leakValue {
		t.Fatalf("非凭证键复合值应保留: %v", c["note"])
	}

	// 对照 D：非凭证键 + map（不得清空）
	d, ok := RedactValue(map[string]map[string]string{"note": {"k": leakValue}}).(map[string]map[string]string)
	if !ok {
		t.Fatalf("输出应保持 map[string]map[string]string 形态")
	}
	if d["note"]["k"] != leakValue {
		t.Fatalf("非凭证键复合值应保留: %v", d["note"])
	}

	// 对照 E：凭证键 + int 元素（数字非凭据文本，维持原值——maskValueFor 免责）
	e, ok := RedactValue(map[string]int{"api_key": 12345}).(map[string]int)
	if !ok {
		t.Fatalf("输出应保持 map[string]int 形态")
	}
	if e["api_key"] != 12345 {
		t.Fatalf("数字凭证键应保持原值: %v", e["api_key"])
	}

	// 对照 F：凭证键 + bool 元素
	f, ok := RedactValue(map[string]bool{"api_key": true}).(map[string]bool)
	if !ok {
		t.Fatalf("输出应保持 map[string]bool 形态")
	}
	if !f["api_key"] {
		t.Fatalf("布尔凭证键应保持原值: %v", f["api_key"])
	}
}

// TestCredentialKeyCompositeJSONRoundTrip_Issue162 序列化面：清空后的载荷
// 不含原文，且仍是合法 JSON（下游采集面不因修复降级为 raw 文本）。
func TestCredentialKeyCompositeJSONRoundTrip_Issue162(t *testing.T) {
	in := map[string]any{
		"api_key": []string{leakValue},
		"note":    "plain",
	}
	out := RedactJSONOpts(mustMarshal(t, in), ValueOptions{})
	if !json.Valid(out) {
		t.Fatalf("输出应为合法 JSON: %s", out)
	}
	if strings.Contains(string(out), leakValue) {
		t.Fatalf("凭证键原文不得落盘: %s", out)
	}
	if !strings.Contains(string(out), "plain") {
		t.Fatalf("非凭证值应保留: %s", out)
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
