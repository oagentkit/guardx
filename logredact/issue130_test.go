package logredact

import "testing"

// 本文件钉 guardx#130 的回归：RedactValue / RedactPayloadValue 的 struct 反射
// 下探必须读 json tag——键名判定（凭证词表、载荷字段白名单、IsCredentialKey
// 回调）此前一律用 Go 字段名（大小写敏感、不读 tag），同一份数据走
// map[string]any（键 api_key）整值打码、走 struct（字段 APIKeyField、tag
// api_key）词表判负原文落库。Go 惯例禁止字段名带下划线，凭证键只能活在
// tag 里——struct 路径不认 tag 就是修复面自身的静默漏脱。

type issue130Payload struct {
	Content     string `json:"content"`
	APIKeyField string `json:"api_key"`
}

// TestRedactStructReadsJSONTag issue 复现：struct 形态下 tag 名 api_key 命中
// 凭证词表整值打码、载荷白名单按 tag 名裁剪——与 map 形态同一口径。
func TestRedactStructReadsJSONTag(t *testing.T) {
	v := issue130Payload{Content: "hello world payload", APIKeyField: "plain-secret-value"}

	// 对照（既有行为）：map 形态整值打码 + 载荷裁剪
	m := RedactPayloadValue(map[string]any{"content": "hello world payload", "api_key": "plain-secret-value"}, "content").(map[string]any)
	if m["api_key"] != "****" {
		t.Fatalf("map 形态 api_key 应打码（对照）: %v", m["api_key"])
	}
	if m["content"] != "<19 bytes scrubbed>" {
		t.Fatalf("map 形态 content 应裁剪（对照）: %v", m["content"])
	}

	// 缺陷本体：struct 形态同一份数据
	got := RedactPayloadValue(v, "content").(issue130Payload)
	if got.APIKeyField != "****" {
		t.Fatalf("struct 形态应读 json tag：api_key 整值泄漏为 %q", got.APIKeyField)
	}
	if got.Content != "<19 bytes scrubbed>" {
		t.Fatalf("struct 形态载荷白名单应按 json tag 裁剪，得到 %q", got.Content)
	}
}

// TestRedactStructCredentialKeyReceivesJSONName ValueOptions.IsCredentialKey
// 回调在 struct 路径收到的是 json tag 名（调用方按 JSON 名补救的入口）。
// 键名选内置词表**不**命中的（内置命中的键在回调之前就被短路打码）。
func TestRedactStructCredentialKeyReceivesJSONName(t *testing.T) {
	type payload struct {
		TokenField string `json:"tenant_mark"`
	}
	var seen []string
	opts := ValueOptions{IsCredentialKey: func(key string) bool {
		seen = append(seen, key)
		return key == "tenant_mark"
	}}
	got := RedactValueOpts(payload{TokenField: "tok-secret"}, opts).(payload)
	if got.TokenField != "****" {
		t.Fatalf("回调按 json tag 名判定应整值打码，得到 %q", got.TokenField)
	}
	if len(seen) == 0 || seen[0] != "tenant_mark" {
		t.Fatalf("回调应收到 json tag 名 tenant_mark，得到 %v", seen)
	}
}

// TestRedactStructJSONDashTagFallsBackToFieldName tag 为 `-`（明确不序列化）
// 时回落 Go 字段名判定——该字段不进 JSON，但值仍要被走键名判定与文本规则，
// 不得因 tag 而整字段跳过（跳过 = 反射面新增漏脱）。
func TestRedactStructJSONDashTagFallsBackToFieldName(t *testing.T) {
	type payload struct {
		Password string `json:"-"`
		Note     string `json:"note"`
	}
	got := RedactValue(payload{Password: "hunter2", Note: "plain text"}).(payload)
	if got.Password != "****" {
		t.Fatalf("tag `-` 回落字段名判定：Password 应整值打码，得到 %q", got.Password)
	}
	if got.Note != "plain text" {
		t.Fatalf("无关字段不应被改: %q", got.Note)
	}
}
