package logredact

import (
	"strings"
	"testing"
)

// 本文件钉 guardx#132 的回归：凭证词表必须命中「凭证词在键的任意段」——
// 此前只锚键尾段（$ 后缀），password_hash / api_key_prefix / password_salt
// 这类凭证词在中间的键全部判负：结构化面不整值打码、文本面 kv 规则不命中
// （password 后跟 _ 而非 [=:]）、值过形状规则后原文保留。
// #52 契约不动：tokens 复数计量收窄照旧单列——token_expiry 等计量键不得误掩。

// TestCredentialWordMidSegmentJSON JSON 键面：凭证词在中间段的键整值打码，
// 末段键（hash_password）照旧命中，token 计量键照旧保留。
func TestCredentialWordMidSegmentJSON(t *testing.T) {
	in := `{"password_hash":"hunter2-bcrypt","api_key_prefix":"AKIA-preview","password_salt":"salty","hash_password":"legacy-masked","password":"plain","token_expiry":3600,"prompt_tokens":42}`
	out := RedactJSON([]byte(in))
	s := string(out)
	for _, leak := range []string{"hunter2-bcrypt", "AKIA-preview", "salty", `"password":"plain"`} {
		if strings.Contains(s, leak) {
			t.Fatalf("凭证词在中间段的键 %s 泄漏: %s", leak, s)
		}
	}
	for _, want := range []string{`"hash_password":"****"`, `"token_expiry":3600`, `"prompt_tokens":42`} {
		if !strings.Contains(s, want) {
			t.Fatalf("应保留 %s，得到: %s", want, s)
		}
	}
}

// TestCredentialWordMidSegmentValue 结构化值形态（RedactValue）：map 键
// password_hash 整值打码——此前判负原文透传。
func TestCredentialWordMidSegmentValue(t *testing.T) {
	out := RedactValue(map[string]any{
		"password_hash":  "hunter2-bcrypt",
		"api_key_prefix": "AKIA-preview",
		"token_expiry":   3600,
	}).(map[string]any)
	if out["password_hash"] != "****" {
		t.Fatalf("password_hash 应整值打码，得到 %v", out["password_hash"])
	}
	if out["api_key_prefix"] != "****" {
		t.Fatalf("api_key_prefix 应整值打码，得到 %v", out["api_key_prefix"])
	}
	if out["token_expiry"] != 3600 {
		t.Fatalf("#52 计量键不得误掩，得到 %v", out["token_expiry"])
	}
}

// TestCredentialWordMidSegmentText 文本面：kv 规则对「凭证词在中间段」的键
// 整值打码（裸值 / 双引号值两形态），IsCredentialKey 谓词同步命中；反证：
// 无凭证词、#52 计量键不误掩。
func TestCredentialWordMidSegmentText(t *testing.T) {
	cases := []struct{ in, want string }{
		{"password_hash=hunter2-bcrypt", "password_hash=****"},
		{"api_key_prefix=AKIA-preview", "api_key_prefix=****"},
		{"password_salt=salty", "password_salt=****"},
		{"hash_password=hunter2", "hash_password=****"}, // 末段照旧（对照）
		{`{"password_hash": "hunter2-bcrypt"}`, `{"password_hash": "****"}`},
		{"token_expiry=3600", "token_expiry=3600"}, // #52 契约
		{"prompt_tokens=42", "prompt_tokens=42"},   // #52 契约
		{"author_name=张三", "author_name=张三"},       // 无凭证词不误掩（auth 后无分隔段）
	}
	for _, tc := range cases {
		if got := Redact(tc.in); got != tc.want {
			t.Errorf("Redact(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestIsCredentialKeyMidSegment 导出谓词与词表同口径（集成方按它预判）。
func TestIsCredentialKeyMidSegment(t *testing.T) {
	for _, key := range []string{"password_hash", "api_key_prefix", "password_salt", "hash_password", "dbPassword"} {
		if !IsCredentialKey(key) {
			t.Errorf("IsCredentialKey(%q) 应命中", key)
		}
	}
	for _, key := range []string{"token_expiry", "prompt_tokens", "author", "author_name"} {
		if IsCredentialKey(key) {
			t.Errorf("IsCredentialKey(%q) 不应命中（#52 / 无凭证词）", key)
		}
	}
}
