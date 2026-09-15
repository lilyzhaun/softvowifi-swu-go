package eap

import "errors"

// 快速重认证状态
type ReauthState struct {
	NextReauthID string // 下一次重认证 ID (从服务器获取)
	Counter      uint16 // 重认证计数器
	MK           []byte // 主密钥 (来自完整认证)
	KEncr        []byte // 加密密钥
	KAut         []byte // 认证密钥
	MSK          []byte // 主会话密钥
	EMSK         []byte // 扩展主会话密钥
}

// FastReauthContext 快速重认证上下文
type FastReauthContext struct {
	Enabled      bool
	ReauthID     string // 当前重认证 ID
	Counter      uint16
	NonceS       []byte // 服务器 Nonce
	CounterSmall bool   // AT_COUNTER_TOO_SMALL 标志

	// 保存的密钥
	KEncr []byte
	KAut  []byte
	MK    []byte
}

// NewFastReauthContext 创建快速重认证上下文
func NewFastReauthContext() *FastReauthContext {
	return &FastReauthContext{
		Enabled: false,
	}
}

// SaveReauthData 保存重认证数据 (从 AT_NEXT_REAUTH_ID 获取)
func (ctx *FastReauthContext) SaveReauthData(nextReauthID string, mk, kEncr, kAut []byte) {
	ctx.ReauthID = nextReauthID
	ctx.MK = mk
	ctx.KEncr = kEncr
	ctx.KAut = kAut
	ctx.Enabled = true
	ctx.Counter = 0
}

// CanUseReauth 检查是否可以使用快速重认证
func (ctx *FastReauthContext) CanUseReauth() bool {
	return ctx.Enabled && ctx.ReauthID != ""
}

// ErrReauthCounterTooSmall 服务器计数器不大于本地缓存，需回退全量认证
var ErrReauthCounterTooSmall = errors.New("EAP-AKA re-auth counter too small, fallback to full auth")

// BuildReauthResponse 构建重认证响应
// AT_COUNTER + AT_MAC
// 若服务器计数器不大于本地缓存（RFC 4187 §5.4），返回 ErrReauthCounterTooSmall，
// 调用方应回退全量认证
func (ctx *FastReauthContext) BuildReauthResponse(nonceS []byte, counter uint16) ([]byte, error) {
	ctx.NonceS = nonceS

	// RFC 4187 §5.4: 服务器 counter 必须大于客户端上次使用的 counter，
	// 否则客户端应执行全量认证（防重放）
	if counter <= ctx.Counter {
		ctx.CounterSmall = true
		return nil, ErrReauthCounterTooSmall
	}
	ctx.Counter = counter
	ctx.CounterSmall = false

	response := []byte{}

	// AT_COUNTER (固定 4 字节)
	response = append(response, AT_COUNTER, 1) // Type=19, Length=1 (4 bytes)
	response = append(response, byte(counter>>8), byte(counter))

	// AT_MAC 占位（调用方在完整 EAP 消息上计算 MAC 后回填）
	response = append(response, AT_MAC, 5, 0, 0) // Type=11, Length=5
	response = append(response, make([]byte, 16)...)

	return response, nil
}

// 注意: AT_COUNTER, AT_COUNTER_TOO_SMALL, AT_NONCE_S, AT_NEXT_REAUTH_ID
// 已在 packet.go 中定义
