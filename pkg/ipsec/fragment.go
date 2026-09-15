package ipsec

import "encoding/binary"

// 内层 IP 分片（RFC 791 IPv4 / RFC 8200 IPv6 Fragment Header）
// 在 ESP 内部做分片，避免外层 IP 分片破坏 ESP 完整性。
// 参考 vowifi_gateway swu_ike.py 的 SWU_INNER_FRAG 设计（MTU 1400）。

const (
	ipv4HeaderLen   = 20
	ipv6HeaderLen   = 40
	ipv6FragmentLen = 8
)

// FragmentPacket 按 maxSize 对内层 IP 包做分片。
// 返回分片后的多个 IP 包（每个独立 Encapsulate）。
// 包不超过 maxSize 时返回原包（零拷贝）。
func FragmentPacket(packet []byte, maxSize int) [][]byte {
	if len(packet) <= maxSize {
		return [][]byte{packet}
	}
	if len(packet) < 1 {
		return [][]byte{packet}
	}
	switch packet[0] >> 4 {
	case 4:
		return fragmentIPv4(packet, maxSize)
	case 6:
		return fragmentIPv6(packet, maxSize)
	default:
		// 未知版本，原样返回
		return [][]byte{packet}
	}
}

// fragmentIPv4 按 RFC 791 分片 IPv4 包
func fragmentIPv4(packet []byte, maxSize int) [][]byte {
	if len(packet) < ipv4HeaderLen {
		return [][]byte{packet}
	}

	// 原始头
	header := make([]byte, ipv4HeaderLen)
	copy(header, packet[:ipv4HeaderLen])
	payload := packet[ipv4HeaderLen:]

	// 若原始包已带分片偏移（DF=0 且 offset>0），不再分片（对端已在重组）
	fragOffset := int(header[6]&0x1F)<<8 | int(header[7])
	df := header[6]&0x40 != 0
	if fragOffset > 0 || df {
		// DF=1 或已是分片：返回原包（DF=1 时若超 MTU 应回 ICMP，但 VoWiFi 场景交给 TUN MTU 限制）
		return [][]byte{packet}
	}

	// 每个分片的最大 payload（8 字节对齐）
	maxPayload := (maxSize - ipv4HeaderLen) &^ 7
	if maxPayload < 8 {
		return [][]byte{packet}
	}

	totalLen := len(payload)
	var fragments [][]byte
	offset := 0
	fragNum := 0
	for offset < totalLen {
		lenThisFrag := maxPayload
		if offset+lenThisFrag > totalLen {
			lenThisFrag = totalLen - offset
		}

		frag := make([]byte, ipv4HeaderLen+lenThisFrag)
		copy(frag, header)
		// 长度字段
		binary.BigEndian.PutUint16(frag[2:4], uint16(ipv4HeaderLen+lenThisFrag))
		// 偏移字段（8 字节单位），MF 标志
		offUnits := offset / 8
		more := 1
		if offset+lenThisFrag >= totalLen {
			more = 0
		}
		frag[6] = header[6]&0xE0 | byte(offUnits>>8) | byte(more<<5)
		frag[7] = byte(offUnits & 0xFF)
		// 校验和置 0 后重算（RFC 1071）
		frag[10], frag[11] = 0, 0
		checksum := ipv4Checksum(frag[:ipv4HeaderLen])
		frag[10], frag[11] = byte(checksum>>8), byte(checksum&0xFF)
		copy(frag[ipv4HeaderLen:], payload[offset:offset+lenThisFrag])

		fragments = append(fragments, frag)
		offset += lenThisFrag
		fragNum++
	}
	return fragments
}

// ipv4Checksum 计算 IPv4 头校验和（RFC 1071）
func ipv4Checksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		sum += uint32(header[i])<<8 | uint32(header[i+1])
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// fragmentIPv6 按 RFC 8200 分片 IPv6 包（带 Fragment Header）
func fragmentIPv6(packet []byte, maxSize int) [][]byte {
	if len(packet) < ipv6HeaderLen {
		return [][]byte{packet}
	}

	// 原始头（40 字节），需要修改 payload length 和 next header
	header := make([]byte, ipv6HeaderLen)
	copy(header, packet[:ipv6HeaderLen])
	payload := packet[ipv6HeaderLen:]

	// 若已有 Fragment Header（next header == 44），不再分片
	if header[6] == 44 {
		return [][]byte{packet}
	}

	// 每个分片最大 payload（Fragment Header 8 字节 + payload，8 字节对齐）
	maxPayload := (maxSize - ipv6HeaderLen - ipv6FragmentLen) &^ 7
	if maxPayload < 8 {
		return [][]byte{packet}
	}

	// 原始 next header 存到 Fragment Header 里，IPv6 头 next header 改为 44
	origNextHeader := header[6]
	header[6] = 44

	// 原始 identification（从包尾复制 4 字节，RFC 8200 建议用源包尾部数据）
	var id [4]byte
	if len(packet) >= ipv6HeaderLen+4 {
		copy(id[:], packet[len(packet)-4:])
	} else {
		id = [4]byte{0, 0, 0, 1}
	}

	totalLen := len(payload)
	var fragments [][]byte
	offset := 0
	for offset < totalLen {
		lenThisFrag := maxPayload
		if offset+lenThisFrag > totalLen {
			lenThisFrag = totalLen - offset
		}

		frag := make([]byte, ipv6HeaderLen+ipv6FragmentLen+lenThisFrag)
		copy(frag, header)
		// payload length = Fragment Header + 本片 payload
		binary.BigEndian.PutUint16(frag[4:6], uint16(ipv6FragmentLen+lenThisFrag))

		// Fragment Header
		fh := frag[ipv6HeaderLen : ipv6HeaderLen+ipv6FragmentLen]
		fh[0] = origNextHeader
		fh[1] = 0 // reserved
		offUnits := offset / 8
		more := 1
		if offset+lenThisFrag >= totalLen {
			more = 0
		}
		binary.BigEndian.PutUint16(fh[2:4], uint16(offUnits)<<3|uint16(more))
		copy(fh[4:8], id[:])

		copy(frag[ipv6HeaderLen+ipv6FragmentLen:], payload[offset:offset+lenThisFrag])

		fragments = append(fragments, frag)
		offset += lenThisFrag
	}
	return fragments
}
