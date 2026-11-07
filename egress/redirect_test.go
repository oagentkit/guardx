package egress

// 逐跳判定的用例单独成文件：本文件只关心「重定向之后还判不判」这一族。
// 与 client_test.go 的分工：那边判**拨号层**守卫，这边判**写面逐跳**那一半。

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func mustReq(t *testing.T, raw string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		t.Fatalf("构造请求失败：%v", err)
	}
	return req
}

// TestCheckRedirectBlocksPrivateTarget 云元数据地址在**重定向这一跳**被拒。
//
// 这条钉的正是「写面只判首跳」留下的洞：首跳是合法公网域名，302 到 169.254.169.254。
func TestCheckRedirectBlocksPrivateTarget(t *testing.T) {
	err := PublicOnly.CheckRedirect(mustReq(t, "http://169.254.169.254/latest/meta-data"), nil)
	var blocked *BlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("云元数据目标应被拒且原因是 *BlockedError，实际 %T：%v", err, err)
	}
}

// TestCheckRedirectAllowsPublicTarget 放行面内的目标照常放行（判据不能只会拒）。
func TestCheckRedirectAllowsPublicTarget(t *testing.T) {
	if err := PublicOnly.CheckRedirect(mustReq(t, "https://example.test/x"), nil); err != nil {
		t.Fatalf("公网域名应放行，实际：%v", err)
	}
}

// TestCheckRedirectRejectsNonHTTPScheme scheme 白名单在每一跳都生效（fail-closed）。
//
// 用 ftp:// 而不是 file://：后者 host 为空，即使 scheme 判据被摘掉也会被「空 host」
// 顺带拒掉 —— 那样的用例在判据整个失灵时照样绿（等于没钉住）。ftp:// 有合法 host，
// 只有 scheme 白名单能拒它。
func TestCheckRedirectRejectsNonHTTPScheme(t *testing.T) {
	if err := PublicOnly.CheckRedirect(mustReq(t, "ftp://example.test/x"), nil); err == nil {
		t.Fatal("非 http(s) 的跳转目标应被拒")
	}
}

// TestCheckRedirectHopLimitOffByOne 跳数上限与 net/http 同口径，边界必须钉死。
//
// via 装的是**已经发出**的请求：len(via)=9 时本次是第 10 跳（放行），len(via)=10 时
// 是第 11 跳（拒）。差一格的写法（>= 写成 >）两侧都还「看起来合理」——本仓
// netguard 就踩过这个差一（那次是对齐参照实现时才发现的）。
func TestCheckRedirectHopLimitOffByOne(t *testing.T) {
	req := mustReq(t, "https://example.test/x")
	if err := PublicOnly.CheckRedirect(req, make([]*http.Request, maxRedirects-1)); err != nil {
		t.Fatalf("第 %d 跳应放行，实际：%v", maxRedirects, err)
	}
	if err := PublicOnly.CheckRedirect(req, make([]*http.Request, maxRedirects)); err == nil {
		t.Fatalf("第 %d 跳应拒（len(via) >= %d）", maxRedirects+1, maxRedirects)
	}
}

// TestCheckRedirectWiredIntoClient 赋给 http.Client.CheckRedirect 真的拦得住。
//
// 前一族用例直接调函数，证明的是判定本身；这一条证明**接线**：函数签名与
// http.Client 的钩子逐字兼容，且默认跟随行为确实被它接管（首跳放行、跳转被拒）。
// 首跳是回环地址（PublicOnly 拒回环），能发出去本身就说明 CheckRedirect **不判首跳**
// ——首跳归写面管，这里只判跳转。
func TestCheckRedirectWiredIntoClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data", http.StatusFound)
	}))
	defer srv.Close()

	c := srv.Client()
	c.CheckRedirect = PublicOnly.CheckRedirect
	resp, err := c.Get(srv.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("跟随重定向应被 CheckRedirect 拒掉")
	}
	var blocked *BlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("拒绝原因应是 *BlockedError，实际 %T：%v", err, err)
	}
}
