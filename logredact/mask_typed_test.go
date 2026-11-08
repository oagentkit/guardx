package logredact

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// 本文件钉 guardx#101 的回归：Masker.MaskValue / UnmaskValue 必须下探类型化
// 容器（map[string]string / []string / struct / 指针…），与 #63/#76 给
// RedactValue 的反射下探同源——类型开关只认 any 解码形态时，类型化容器
// 落 default 原样返回：零令牌、零报错的静默漏掩，比它替代的
// json.Marshal → Mask → json.Unmarshal 往返更糟。

type maskTypedTop struct {
	Host    string
	Gateway string
	Count   int
}

type maskTypedNamed string

type maskTypedNode struct {
	Next *maskTypedNode
	V    string
}

// TestMaskValueTypedMapAndSlice issue 探针的前两例：类型化 map / slice。
func TestMaskValueTypedMapAndSlice(t *testing.T) {
	m := NewMasker()
	in := map[string]string{"host": "10.0.0.5", "name": "node-a"}
	out, ok := m.MaskValue(in).(map[string]string)
	if !ok {
		t.Fatalf("输出应保持 map[string]string 形态，实得 %T", m.MaskValue(in))
	}
	if out["host"] == "10.0.0.5" || !strings.Contains(out["host"], "«T") {
		t.Fatalf("类型化 map 的 IPv4 值应被掩码: %v", out)
	}
	if out["name"] != "node-a" {
		t.Fatalf("非拓扑标识值应原样: %q", out["name"])
	}
	if in["host"] != "10.0.0.5" {
		t.Fatalf("入参不得被污染: %v", in)
	}

	slice, ok := m.MaskValue([]string{"10.0.0.6", "plain"}).([]string)
	if !ok {
		t.Fatalf("输出应保持 []string 形态，实得 %T", m.MaskValue([]string{"10.0.0.6"}))
	}
	if slice[0] == "10.0.0.6" || !strings.Contains(slice[0], "«T") {
		t.Fatalf("类型化 slice 的 IPv4 元素应被掩码: %v", slice)
	}
	if slice[1] != "plain" {
		t.Fatalf("非拓扑标识元素应原样: %q", slice[1])
	}
}

// TestMaskValueTypedStruct issue 探针的 struct 例：叶子掩码、标量原样、
// 副本不污染入参、逆视图回填无损。
func TestMaskValueTypedStruct(t *testing.T) {
	m := NewMasker()
	in := maskTypedTop{Host: "10.0.0.5", Gateway: "::1", Count: 3}
	out, ok := m.MaskValue(in).(maskTypedTop)
	if !ok {
		t.Fatalf("输出应保持 struct 形态，实得 %T", m.MaskValue(in))
	}
	if out.Host == "10.0.0.5" || !strings.Contains(out.Host, "«T") {
		t.Fatalf("struct 字段 IPv4 应被掩码: %+v", out)
	}
	if out.Gateway == "::1" || !strings.Contains(out.Gateway, "«T") {
		t.Fatalf("struct 字段 IPv6 应被掩码: %+v", out)
	}
	if out.Count != 3 {
		t.Fatalf("非字符串字段应原样: %+v", out)
	}
	if in.Host != "10.0.0.5" || in.Gateway != "::1" {
		t.Fatalf("入参不得被污染: %+v", in)
	}
	back, ok := m.UnmaskValue(out).(maskTypedTop)
	if !ok {
		t.Fatalf("逆视图应保持 struct 形态，实得 %T", m.UnmaskValue(out))
	}
	if !reflect.DeepEqual(back, in) {
		t.Fatalf("回填应无损:\n got %+v\nwant %+v", back, in)
	}
}

// TestMaskValueTypedPointerNestedAndNamed 指针、嵌套类型化容器、命名 string、
// json.Number 特赦、[]byte 豁免、nil 容器。
func TestMaskValueTypedPointerNestedAndNamed(t *testing.T) {
	m := NewMasker()

	p := &maskTypedTop{Host: "10.0.0.5", Count: 1}
	out, ok := m.MaskValue(p).(*maskTypedTop)
	if !ok {
		t.Fatalf("输出应保持 *struct 形态，实得 %T", m.MaskValue(p))
	}
	if !strings.Contains(out.Host, "«T") {
		t.Fatalf("指针 struct 的 IPv4 字段应被掩码: %+v", out)
	}
	if p.Host != "10.0.0.5" {
		t.Fatalf("入参指针不得被污染: %+v", p)
	}

	nested := map[string][]maskTypedTop{
		"peers": {{Host: "10.0.0.7", Count: 2}},
	}
	outNested, ok := m.MaskValue(nested).(map[string][]maskTypedTop)
	if !ok {
		t.Fatalf("输出应保持 map[string][]struct 形态，实得 %T", m.MaskValue(nested))
	}
	if !strings.Contains(outNested["peers"][0].Host, "«T") {
		t.Fatalf("嵌套类型化容器的 IPv4 应被掩码: %+v", outNested)
	}

	namedVal := struct {
		HostID maskTypedNamed
		Note   string
	}{HostID: "10.0.0.8", Note: "plain"}
	outNamed, ok := m.MaskValue(namedVal).(struct {
		HostID maskTypedNamed
		Note   string
	})
	if !ok {
		t.Fatalf("输出应保持命名 string 字段的 struct 形态，实得 %T", m.MaskValue(namedVal))
	}
	if !strings.Contains(string(outNamed.HostID), "«T") {
		t.Fatalf("命名 string 字段应被掩码: %+v", outNamed)
	}
	backNamed := m.UnmaskValue(outNamed).(struct {
		HostID maskTypedNamed
		Note   string
	})
	if backNamed.HostID != maskTypedNamed("10.0.0.8") {
		t.Fatalf("命名 string 回填后应还原且保型: %#v", backNamed.HostID)
	}

	num := struct {
		N json.Number
		S string
	}{N: "12345", S: "10.0.0.9"}
	outNum := m.MaskValue(num).(struct {
		N json.Number
		S string
	})
	if outNum.N != "12345" {
		t.Fatalf("json.Number 是数字字面量不是文本，应特赦: %+v", outNum)
	}
	if !strings.Contains(outNum.S, "«T") {
		t.Fatalf("同结构体的字符串字段仍应掩码: %+v", outNum)
	}

	raw := []byte("10.0.0.10 payload")
	if out := m.MaskValue(raw).([]byte); string(out) != string(raw) {
		t.Fatalf("[]byte 是二进制载荷应豁免: %q", out)
	}

	var nilMap map[string]string
	if out, ok := m.MaskValue(nilMap).(map[string]string); !ok || out != nil {
		t.Fatalf("nil map 应原样返回，实得 %v", out)
	}
	var nilSlice []string
	if out, ok := m.MaskValue(nilSlice).([]string); !ok || out != nil {
		t.Fatalf("nil slice 应原样返回，实得 %v", out)
	}
	var nilPtr *maskTypedTop
	if out, ok := m.MaskValue(nilPtr).(*maskTypedTop); !ok || out != nil {
		t.Fatalf("nil 指针应原样返回，实得 %v", out)
	}
}

// TestMaskValueTypedSelfReferenceTerminates 类型化容器可自引用（JSON 解码值
// 不可能成环，Go 值可以）——walk 必须有深度上限兜底，不能栈溢出挂死掩码链路。
func TestMaskValueTypedSelfReferenceTerminates(t *testing.T) {
	m := NewMasker()
	n := &maskTypedNode{V: "10.0.0.5"}
	n.Next = n // 成环
	out, ok := m.MaskValue(n).(*maskTypedNode)
	if !ok {
		t.Fatalf("输出应保持 *struct 形态，实得 %T", m.MaskValue(n))
	}
	if !strings.Contains(out.V, "«T") {
		t.Fatalf("成环结构的外层字段仍应被掩码: %+v", out.V)
	}
}
