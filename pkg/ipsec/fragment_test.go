package ipsec

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// fragmentIPv4 测试：1500 字节 IPv4 包按 1358 分片，重组后一致
func TestFragmentIPv4(t *testing.T) {
	// 构造 1500 字节 IPv4 包（20 头 + 1480 payload）
	pkt := make([]byte, 1500)
	pkt[0] = 0x45 // IPv4, IHL=5
	binary.BigEndian.PutUint16(pkt[2:4], 1500)
	pkt[9] = 17 // UDP
	for i := 20; i < 1500; i++ {
		pkt[i] = byte(i % 251)
	}
	// 计算原始头校验和
	cs := ipv4Checksum(pkt[:20])
	pkt[10], pkt[11] = byte(cs>>8), byte(cs&0xFF)

	frags := FragmentPacket(pkt, 1358)
	if len(frags) < 2 {
		t.Fatalf("预期至少 2 个分片，得到 %d", len(frags))
	}
	for i, f := range frags {
		if len(f) > 1358 {
			t.Fatalf("分片 %d 超过 MTU: %d", i, len(f))
		}
		if f[0]>>4 != 4 {
			t.Fatalf("分片 %d 不是 IPv4", i)
		}
	}

	// 重组
	reassembled := reassembleIPv4(t, frags)
	if !bytes.Equal(reassembled, pkt) {
		t.Fatalf("重组结果与原始包不一致: got %d bytes, want %d", len(reassembled), len(pkt))
	}
}

// 小包不分片
func TestFragmentSmallPacket(t *testing.T) {
	pkt := make([]byte, 500)
	pkt[0] = 0x45
	frags := FragmentPacket(pkt, 1358)
	if len(frags) != 1 {
		t.Fatalf("小包不应分片，得到 %d 片", len(frags))
	}
	if !bytes.Equal(frags[0], pkt) {
		t.Fatalf("小包应原样返回")
	}
}

// fragmentIPv6 测试
func TestFragmentIPv6(t *testing.T) {
	// 构造 1500 字节 IPv6 包（40 头 + 1460 payload）
	pkt := make([]byte, 1500)
	pkt[0] = 0x60 // IPv6
	binary.BigEndian.PutUint16(pkt[4:6], 1460)
	pkt[6] = 17 // next header: UDP
	for i := 40; i < 1500; i++ {
		pkt[i] = byte(i % 251)
	}

	frags := FragmentPacket(pkt, 1358)
	if len(frags) < 2 {
		t.Fatalf("预期至少 2 个分片，得到 %d", len(frags))
	}
	for i, f := range frags {
		if len(f) > 1358 {
			t.Fatalf("分片 %d 超过 MTU: %d", i, len(f))
		}
		if f[0]>>4 != 6 {
			t.Fatalf("分片 %d 不是 IPv6", i)
		}
		if f[6] != 44 {
			t.Fatalf("分片 %d 的 next header 应为 44 (Fragment)，得到 %d", i, f[6])
		}
	}

	// 重组
	reassembled := reassembleIPv6(t, frags)
	if !bytes.Equal(reassembled, pkt) {
		t.Fatalf("IPv6 重组结果与原始包不一致: got %d bytes, want %d", len(reassembled), len(pkt))
	}
}

func reassembleIPv4(t *testing.T, frags [][]byte) []byte {
	t.Helper()
	// 分片后各片 header 长度字段是片长；总长 = 头 + 所有 payload 之和
	total := 20
	for _, f := range frags {
		total += len(f) - 20
	}
	out := make([]byte, total)
	copy(out[:20], frags[0][:20])
	// 恢复原始头：总长度字段 + 清 MF/offset（保留 DF/保留位）+ 重算校验和
	binary.BigEndian.PutUint16(out[2:4], uint16(total))
	out[6] &= 0xC0
	out[7] = 0
	out[10], out[11] = 0, 0
	cs := ipv4Checksum(out[:20])
	out[10], out[11] = byte(cs>>8), byte(cs&0xFF)
	for _, f := range frags {
		offUnits := int(f[6]&0x1F)<<8 | int(f[7])
		offset := offUnits * 8
		plen := len(f) - 20
		copy(out[20+offset:], f[20:20+plen])
	}
	return out
}

func reassembleIPv6(t *testing.T, frags [][]byte) []byte {
	t.Helper()
	header := make([]byte, 40)
	copy(header, frags[0][:40])
	origNext := frags[0][40]
	header[6] = origNext
	total := 40
	for _, f := range frags {
		total += len(f) - 48
	}
	out := make([]byte, total)
	copy(out[:40], header)
	binary.BigEndian.PutUint16(out[4:6], uint16(total-40))
	for _, f := range frags {
		fh := f[40:48]
		offUnits := int(binary.BigEndian.Uint16(fh[2:4])) >> 3
		offset := offUnits * 8
		plen := len(f) - 48
		copy(out[40+offset:], f[48:48+plen])
	}
	return out
}
