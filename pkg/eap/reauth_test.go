package eap

import (
	"errors"
	"testing"
)

// 服务器计数器大于本地 → 正常构建响应
func TestBuildReauthResponseNormal(t *testing.T) {
	ctx := NewFastReauthContext()
	ctx.SaveReauthData("reauth-id-1", []byte("mk"), []byte("kencr"), []byte("kaut"))
	ctx.Counter = 5

	resp, err := ctx.BuildReauthResponse([]byte("nonce-s"), 10)
	if err != nil {
		t.Fatalf("正常 re-auth 不应报错: %v", err)
	}
	if len(resp) == 0 {
		t.Fatalf("响应不应为空")
	}
	if ctx.CounterSmall {
		t.Fatalf("正常 re-auth 不应设置 CounterSmall")
	}
	// 响应应含 AT_COUNTER(19) + AT_MAC(11)
	if resp[0] != AT_COUNTER {
		t.Fatalf("第一个属性应为 AT_COUNTER，得到 %d", resp[0])
	}
}

// 服务器计数器等于本地 → CounterSmall + 错误
func TestBuildReauthResponseEqualCounter(t *testing.T) {
	ctx := NewFastReauthContext()
	ctx.SaveReauthData("reauth-id-1", []byte("mk"), []byte("kencr"), []byte("kaut"))
	ctx.Counter = 10

	_, err := ctx.BuildReauthResponse([]byte("nonce-s"), 10)
	if !errors.Is(err, ErrReauthCounterTooSmall) {
		t.Fatalf("相等 counter 应返回 ErrReauthCounterTooSmall，得到 %v", err)
	}
	if !ctx.CounterSmall {
		t.Fatalf("相等 counter 应设置 CounterSmall")
	}
}

// 服务器计数器小于本地 → CounterSmall + 错误
func TestBuildReauthResponseSmallerCounter(t *testing.T) {
	ctx := NewFastReauthContext()
	ctx.SaveReauthData("reauth-id-1", []byte("mk"), []byte("kencr"), []byte("kaut"))
	ctx.Counter = 20

	_, err := ctx.BuildReauthResponse([]byte("nonce-s"), 5)
	if !errors.Is(err, ErrReauthCounterTooSmall) {
		t.Fatalf("较小 counter 应返回 ErrReauthCounterTooSmall，得到 %v", err)
	}
}

// 无假名缓存 → CanUseReauth 为 false
func TestCanUseReauth(t *testing.T) {
	ctx := NewFastReauthContext()
	if ctx.CanUseReauth() {
		t.Fatalf("初始状态不应可用 re-auth")
	}
	ctx.SaveReauthData("reauth-id-1", []byte("mk"), []byte("kencr"), []byte("kaut"))
	if !ctx.CanUseReauth() {
		t.Fatalf("保存假名后应可用 re-auth")
	}
}
