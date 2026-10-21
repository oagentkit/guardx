package wire

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
)

// Client 子侧客户端：程序在子进程里用它向父侧请求工具调用。
//
// # 与 Transport 的方向相反
//
// Transport 是**父侧**用的（父侧发起调用、收响应）；Client 是**子侧**用的
// （子侧发起调用、收响应）。两者共用同一套帧格式与「按 id 关联」语义——
// 协议只有一份，两个方向只是角色不同。
//
// # 取消传播（不变量 5）
//
// 父侧 ctx 取消 → 父侧关闭传输端 → 子侧读到 EOF → 本客户端的在途调用全部失败。
// 子侧不需要额外的取消通道：连接断本身就是最强的取消信号。
type Client struct {
	mu sync.Mutex
	// w 写端。
	w io.Writer
	// r 读端。
	r io.Reader
	// pending 在途请求：id → 等待中的响应通道。
	pending map[string]chan Response
	// seq 请求序号（生成唯一 id）。
	seq atomic.Uint64
	// closed 已关闭。
	closed bool
	// closeErr 关闭原因。
	closeErr error
	// readErr 读循环终止原因。
	readErr error
	// writeMu 串行化写。
	writeMu sync.Mutex
}

// NewClient 构造子侧客户端。启动即有读循环 goroutine。
func NewClient(rw io.ReadWriter) *Client {
	c := &Client{
		r:       rw,
		w:       rw,
		pending: map[string]chan Response{},
	}
	go c.readLoop()
	return c
}

// readLoop 读循环：按 id 分发响应（不变量 6）。
func (c *Client) readLoop() {
	for {
		var resp Response
		if err := ReadFrame(c.r, &resp); err != nil {
			c.failAll(err)
			return
		}
		if err := checkVersion(resp.V); err != nil {
			c.failAll(err)
			return
		}
		c.mu.Lock()
		ch, ok := c.pending[resp.ID]
		if ok {
			delete(c.pending, resp.ID)
		}
		c.mu.Unlock()
		if ok {
			ch <- resp
		}
	}
}

// failAll 让所有在途调用失败。
func (c *Client) failAll(err error) {
	c.mu.Lock()
	c.readErr = err
	c.closeErr = err
	c.closed = true
	pending := c.pending
	c.pending = map[string]chan Response{}
	c.mu.Unlock()
	for _, ch := range pending {
		close(ch)
	}
}

// Call 向父侧发起一次工具调用并等待响应。
//
// id 省略时自动生成（保证一次执行内唯一）。
func (c *Client) Call(ctx context.Context, tool, args string) (Response, error) {
	id := fmt.Sprintf("c-%d", c.seq.Add(1))
	return c.CallWithID(ctx, id, tool, args)
}

// CallWithID 用指定 id 发起调用。
func (c *Client) CallWithID(ctx context.Context, id, tool, args string) (Response, error) {
	if id == "" {
		return Response{}, errors.New("wire: 请求 ID 不得为空")
	}
	if tool == "" {
		return Response{}, errors.New("wire: 工具名不得为空")
	}
	ch := make(chan Response, 1)
	c.mu.Lock()
	if c.closed {
		err := c.closeErr
		c.mu.Unlock()
		return Response{}, fmt.Errorf("wire: 客户端已关闭: %w", err)
	}
	c.pending[id] = ch
	c.mu.Unlock()

	req := Request{V: Version, ID: id, Tool: tool, Args: args}
	c.writeMu.Lock()
	err := WriteFrame(c.w, req)
	c.writeMu.Unlock()
	if err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return Response{}, err
	}

	select {
	case resp, ok := <-ch:
		if !ok {
			c.mu.Lock()
			err := c.readErr
			c.mu.Unlock()
			return Response{}, fmt.Errorf("wire: 父侧连接已断: %w", err)
		}
		return resp, nil
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return Response{}, ctx.Err()
	}
}

// Close 关闭客户端（幂等）。
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.closeErr = errors.New("wire: 客户端已关闭")
	c.mu.Unlock()
	c.failAll(c.closeErr)
	return nil
}
