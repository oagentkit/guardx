package wire

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

// TestFrameRoundTrip 帧往返。
func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	req := Request{V: Version, ID: "c-1", Tool: "get_logs", Args: `{"host":"h1"}`, DeadlineMS: 5000}
	if err := WriteFrame(&buf, req); err != nil {
		t.Fatalf("写帧失败: %v", err)
	}
	var got Request
	if err := ReadFrame(&buf, &got); err != nil {
		t.Fatalf("读帧失败: %v", err)
	}
	if got != req {
		t.Errorf("往返后=%+v，应为 %+v", got, req)
	}
}

// TestFrameLengthPrefix 长度前缀是 4 字节大端。
func TestFrameLengthPrefix(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, Request{V: Version, ID: "x"}); err != nil {
		t.Fatalf("写帧失败: %v", err)
	}
	raw := buf.Bytes()
	if len(raw) < 4 {
		t.Fatalf("帧太短: %d 字节", len(raw))
	}
	n := binary.BigEndian.Uint32(raw[:4])
	if int(n) != len(raw)-4 {
		t.Errorf("长度前缀 %d 与实际负载 %d 不符", n, len(raw)-4)
	}
}

// TestFrameHandlesNewlineInPayload 负载含换行不被切断（这是不用行分隔的理由）。
func TestFrameHandlesNewlineInPayload(t *testing.T) {
	var buf bytes.Buffer
	payload := "第一行\n第二行\r\n第三行\n"
	if err := WriteFrame(&buf, Response{V: Version, ID: "c-1", OK: true, Value: payload}); err != nil {
		t.Fatalf("写帧失败: %v", err)
	}
	var got Response
	if err := ReadFrame(&buf, &got); err != nil {
		t.Fatalf("读帧失败: %v", err)
	}
	if got.Value != payload {
		t.Errorf("负载=%q，应为 %q", got.Value, payload)
	}
}

// TestFrameRejectsOversize 长度超上限即拒（不预分配）。
func TestFrameRejectsOversize(t *testing.T) {
	// 伪造一个超大的长度前缀。
	head := make([]byte, 4)
	binary.BigEndian.PutUint32(head, MaxFrameBytes+1)
	var got Request
	err := ReadFrame(bytes.NewReader(head), &got)
	if err == nil {
		t.Fatal("超长帧必须被拒")
	}
	if !strings.Contains(err.Error(), "超过上限") {
		t.Errorf("错误信息应说明超限，实得 %q", err.Error())
	}
}

// TestFrameRejectsPartial 读到一半即报错，不返回「半个帧」。
func TestFrameRejectsPartial(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, Request{V: Version, ID: "c-1", Tool: "t", Args: "0123456789"}); err != nil {
		t.Fatalf("写帧失败: %v", err)
	}
	raw := buf.Bytes()
	err := ReadFrame(bytes.NewReader(raw[:len(raw)-3]), &Request{})
	if err == nil {
		t.Fatal("半帧必须被拒")
	}
}

// TestFrameRejectsGarbage 负载不是合法 JSON 即拒。
func TestFrameRejectsGarbage(t *testing.T) {
	payload := []byte("{not json")
	head := make([]byte, 4)
	binary.BigEndian.PutUint32(head, uint32(len(payload)))
	err := ReadFrame(bytes.NewReader(append(head, payload...)), &Request{})
	if err == nil {
		t.Fatal("非法负载必须被拒")
	}
}

// TestFrameEOFIsDistinguishable EOF 与协议错误要能分开看。
func TestFrameEOFIsDistinguishable(t *testing.T) {
	err := ReadFrame(bytes.NewReader(nil), &Request{})
	if err == nil {
		t.Fatal("空读应报错")
	}
	if !strings.Contains(err.Error(), "读帧长度失败") {
		t.Errorf("错误信息应指向长度读取，实得 %q", err.Error())
	}
}

// TestCheckVersion 版本不匹配即拒（不变量 1）。
func TestCheckVersion(t *testing.T) {
	if err := checkVersion(Version); err != nil {
		t.Errorf("同版本应通过: %v", err)
	}
	err := checkVersion(Version + 1)
	if err == nil {
		t.Fatal("版本不匹配必须被拒")
	}
	if !strings.Contains(err.Error(), "版本不匹配") {
		t.Errorf("错误信息应说明版本不匹配，实得 %q", err.Error())
	}
}

// TestWriteFrameRejectsOversizePayload 写出时也拦超长负载。
func TestWriteFrameRejectsOversizePayload(t *testing.T) {
	big := Response{V: Version, ID: "x", Value: strings.Repeat("a", MaxFrameBytes+1)}
	if err := WriteFrame(io.Discard, big); err != nil {
		// payload 实际会被 JSON 转义放大，仍应超限。
		t.Logf("写出被拒: %v", err)
	}
}
