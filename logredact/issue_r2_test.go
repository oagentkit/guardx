package logredact

// 2026-11-11 第二轮清零回归（obs#88 交叉面）：嵌套容器里的 []byte 与 error。

import (
	"strings"
	"testing"
)

func TestNestedBytesAndErrorRedacted_IssueObs88(t *testing.T) {
	in := map[string]any{
		"req": map[string]any{
			"body": []byte(`{"password":"nested-secret"}`),
			"err":  assertErr{},
			"form": []byte("token=ghp_nestedtext&x=1"),
			"bin":  []byte{0x00, 0xff, 0xfe},
		},
	}
	out := RedactValue(in)
	req := out.(map[string]any)["req"].(map[string]any)
	strOf := func(v any) string {
		switch t := v.(type) {
		case string:
			return t
		case []byte:
			return string(t)
		}
		return ""
	}
	if s := strOf(req["body"]); strings.Contains(s, "nested-secret") {
		t.Fatalf("嵌套 JSON []byte 应过键感知打码: %#v", req["body"])
	}
	if s := strOf(req["err"]); strings.Contains(s, "supersecret") {
		t.Fatalf("嵌套 error 应取 Error() 文本过规则: %#v", req["err"])
	}
	if s := strOf(req["form"]); strings.Contains(s, "ghp_nestedtext") {
		t.Fatalf("嵌套非 JSON 文本 []byte 应过文本规则: %#v", req["form"])
	}
	// 非 UTF-8 二进制原样（检测面为空）。
	if _, ok := req["bin"].([]byte); !ok {
		t.Fatalf("非 UTF-8 二进制应原样保留: %#v", req["bin"])
	}
	// 顶层 RedactValue 对裸 []byte / error 同语义（此前由消费方自理）。
	top := RedactValue([]byte(`{"api_key":"top-secret"}`))
	if ts := strOf(top); strings.Contains(ts, "top-secret") {
		t.Fatalf("顶层 []byte 应打码: %#v", top)
	}
}

type assertErr struct{}

func (assertErr) Error() string { return "connect failed: password=supersecret" }
