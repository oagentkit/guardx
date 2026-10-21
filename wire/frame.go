package wire

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// Version 协议版本。
//
// **不匹配即响亮失败**（不变量 1）：静默错配的症状是「字段读成了另一个意思」——
// 那是最难查的一类错误，故版本对不上直接拒，不试图「兼容」。
const Version = 1

// MaxFrameBytes 单帧负载上限（字节）。
//
// 长度前缀是 4 字节，理论上限 4GB——但那是**攻击面**：一个坏的长度前缀就能让
// 接收方预分配几 GB。故设上限，超限即拒。
//
// 默认 16MB 覆盖了「工具返回一个大结果」的常见情形（宿主侧另有 MaxBytes 预算
// 逐次把关，见不变量 3）。
const MaxFrameBytes = 16 << 20

// Request 一次工具调用请求帧（子进程 → 父侧）。
//
// Args 是**原始参数串**（通常是 JSON 文本），不解析成结构体——协议不该替宿主
// 决定工具参数长什么样（那是宿主的工具面知识）。
type Request struct {
	// V 协议版本。
	V int `json:"v"`
	// ID 调用标识。响应按它关联（不变量 6），故**必须非空且在一次执行内唯一**。
	ID string `json:"id"`
	// Tool 工具名。
	Tool string `json:"tool"`
	// Args 工具参数原文（宿主侧按自己的工具面解析）。
	Args string `json:"args"`
	// DeadlineMS 本次调用的期限（毫秒）。0 = 不限期。
	//
	// 由**子进程**声明、**父侧**执行：父侧是记账与取消的权威（不变量 3/5），
	// 子进程说了不算，父侧必须自己兜住。
	DeadlineMS int64 `json:"deadline_ms,omitempty"`
}

// Response 一次调用响应帧（父侧 → 子进程）。
type Response struct {
	// V 协议版本。
	V int `json:"v"`
	// ID 对应的请求标识（不变量 6）。
	ID string `json:"id"`
	// OK 本次调用是否成功。
	OK bool `json:"ok"`
	// Value 成功时的结果文本（编码由宿主工具面定）。
	Value string `json:"value,omitempty"`
	// Kind 失败时的分类（**toolfail.Class**，不变量 2）。
	//
	// 空串只允许在「不是工具失败」的场合（如协议层错误、父侧拒绝）——那类错误由
	// 父侧直接终止执行域，不走正常响应路径。
	Kind string `json:"kind,omitempty"`
	// Error 失败时的可读原因（给人看，不参与判定）。
	Error string `json:"error,omitempty"`
}

// WriteFrame 写一帧：4 字节大端长度 + JSON 负载。
//
// 一次 Write 发出整帧（长度前缀与负载合并进同一个缓冲）——分两次写会让
// 对端在两次之间读到半个帧，虽然不至于错乱，但会让并发场景下的帧交错变得可能。
func WriteFrame(w io.Writer, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("wire: 帧序列化失败: %w", err)
	}
	if len(payload) > MaxFrameBytes {
		return fmt.Errorf("wire: 帧负载 %d 字节超过上限 %d", len(payload), MaxFrameBytes)
	}
	buf := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(payload)))
	copy(buf[4:], payload)
	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("wire: 帧写出失败: %w", err)
	}
	return nil
}

// ReadFrame 读一帧：读 4 字节大端长度，再读该长度的 JSON 负载。
//
// 长度超上限即拒（不预分配）——长度前缀是外部输入，不能信。
// 读到一半（EOF / 连接断）即报错，不返回「半个帧」。
func ReadFrame(r io.Reader, v any) error {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return fmt.Errorf("wire: 读帧长度失败: %w", err)
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > MaxFrameBytes {
		return fmt.Errorf("wire: 帧长度 %d 超过上限 %d", n, MaxFrameBytes)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return fmt.Errorf("wire: 读帧负载失败（声明 %d 字节）: %w", n, err)
	}
	if err := json.Unmarshal(payload, v); err != nil {
		return fmt.Errorf("wire: 帧反序列化失败: %w", err)
	}
	return nil
}

// checkVersion 校验帧版本；不匹配即拒（不变量 1）。
func checkVersion(v int) error {
	if v != Version {
		return fmt.Errorf("wire: 协议版本不匹配：收到 %d，本端 %d", v, Version)
	}
	return nil
}
