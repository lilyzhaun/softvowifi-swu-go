package swu

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"

	"github.com/1239t/swu-go/pkg/eap"
	"github.com/1239t/swu-go/pkg/logger"
	"go.uber.org/zap"
)

func (s *Session) logAKARequestStructure(attrs map[uint8]*eap.Attribute) {
	fields := []zap.Field{logger.String("phase", "request")}
	checkcodeStatus, biddingStatus := "absent", "absent"
	if attr, ok := attrs[eap.AT_CHECKCODE]; ok {
		checkcodeStatus = "invalid"
		if len(attr.Value) == 2 || len(attr.Value) == 22 {
			checkcodeStatus = "valid"
			fields = append(fields, logger.Int("checkcode_octets", len(attr.Value)-2), logger.Bool("checkcode_empty", len(attr.Value) == 2))
		}
	}
	if attr, ok := attrs[eap.AT_BIDDING]; ok {
		biddingStatus = "invalid"
		if len(attr.Value) == 2 {
			biddingStatus = "valid"
			fields = append(fields, logger.Bool("bidding_d", binary.BigEndian.Uint16(attr.Value)&0x8000 != 0))
		}
	}
	fields = append(fields, logger.String("checkcode_status", checkcodeStatus), logger.String("bidding_status", biddingStatus))
	s.Logger.Info("AKA structure", fields...)
}

type akaMACOutcome uint8

const (
	akaMACInvalid akaMACOutcome = iota
	akaMACSkipped
	akaMACIKCK
	akaMACCKIK
)

func (s *Session) logAKARequestMAC(outcome akaMACOutcome) {
	fields := []zap.Field{logger.String("phase", "request_mac")}
	status, order := "invalid", ""
	switch outcome {
	case akaMACInvalid:
	case akaMACSkipped:
		status = "skipped"
	case akaMACIKCK:
		status, order = "verified", "ik_ck"
	case akaMACCKIK:
		status, order = "verified", "ck_ik"
	}
	fields = append(fields, logger.String("mac_status", status), logger.Bool("verified", status == "verified"))
	if order != "" {
		fields = append(fields, logger.String("derivation_order", order))
	}
	s.Logger.Info("AKA structure", fields...)
}

type akaResponseExpectation struct {
	identifier uint8
	resOctets  int
}

func (s *Session) logAKAResponseStructure(raw, kAut []byte, expected akaResponseExpectation) {
	invalid := func() {
		s.Logger.Info("AKA structure", logger.String("phase", "response"), logger.String("parse_error", "invalid_response"))
	}
	packet, err := eap.Parse(raw)
	if err != nil || len(raw) < 8 || int(binary.BigEndian.Uint16(raw[2:4])) != len(raw) || packet.Code != eap.CodeResponse || packet.Type != eap.TypeAKA || packet.Subtype != eap.SubtypeChallenge {
		invalid()
		return
	}
	attrs, err := eap.ParseAttributes(packet.Data)
	resAttr, macAttr := attrs[eap.AT_RES], attrs[eap.AT_MAC]
	if err != nil || len(packet.Data)%4 != 0 || resAttr == nil || len(resAttr.Value) < 2+expected.resOctets || macAttr == nil || len(macAttr.Value) != 18 {
		invalid()
		return
	}
	offset, ok := findEAPAttrOffset(packet.Data, eap.AT_MAC)
	macStart := 8 + offset + 4
	if !ok || macStart+16 > len(raw) {
		invalid()
		return
	}
	paddingZero := true
	for _, octet := range resAttr.Value[2+expected.resOctets:] {
		if octet != 0 {
			paddingZero = false
		}
	}
	unsigned := bytes.Clone(raw)
	clear(unsigned[macStart : macStart+16])
	mac := hmac.New(sha1.New, kAut)
	mac.Write(unsigned)
	s.Logger.Info("AKA structure", logger.String("phase", "response"),
		logger.Int("res_len_octets", expected.resOctets), logger.Int("declared_res_bits", int(binary.BigEndian.Uint16(resAttr.Value[:2]))),
		logger.Bool("padding_zero", paddingZero), logger.Bool("eap_identifier_matches", packet.Identifier == expected.identifier),
		logger.Bool("local_mac_valid", hmac.Equal(mac.Sum(nil)[:16], macAttr.Value[2:])))
}
