package swu

import (
	"encoding/binary"
	"errors"
	"slices"

	"github.com/1239t/swu-go/pkg/eap"
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/logger"
	"github.com/1239t/swu-go/pkg/sim"
	"go.uber.org/zap"
)

type eapDiagnosticError string

const (
	eapDiagnosticValid          eapDiagnosticError = ""
	eapDiagnosticPacketError    eapDiagnosticError = "invalid_packet"
	eapDiagnosticAttributeError eapDiagnosticError = "invalid_attributes"
)

type eapDirection string

const (
	eapReceived eapDirection = "received"
	eapSent     eapDirection = "send_attempt"
)

type eapMetadata struct {
	code, method, subtype uint8
	attrTypes             []int
	attrCount             int
	parseError            eapDiagnosticError
}

func parseEAPMetadata(raw []byte) eapMetadata {
	invalid := eapMetadata{parseError: eapDiagnosticPacketError}
	if len(raw) < 4 {
		return invalid
	}
	length := int(binary.BigEndian.Uint16(raw[2:4]))
	if length < 4 || length > len(raw) {
		return invalid
	}
	if raw[0] == eap.CodeRequest || raw[0] == eap.CodeResponse {
		if length < 5 {
			return invalid
		}
		if (raw[4] == eap.TypeAKA || raw[4] == eap.TypeAKAPrime) && length < 8 {
			return invalid
		}
	}
	packet, err := eap.Parse(raw)
	if err != nil {
		return invalid
	}
	metadata := eapMetadata{code: packet.Code, method: packet.Type, subtype: packet.Subtype, attrTypes: []int{}}
	switch packet.Type {
	case eap.TypeAKA, eap.TypeAKAPrime:
		attrs, err := eap.ParseAttributes(packet.Data)
		if err != nil || len(packet.Data)%4 != 0 {
			metadata.parseError = eapDiagnosticAttributeError
			return metadata
		}
		for attrType := range attrs {
			metadata.attrTypes = append(metadata.attrTypes, int(attrType))
		}
		slices.Sort(metadata.attrTypes)
		metadata.attrCount = len(metadata.attrTypes)
		if metadata.attrCount > 64 {
			metadata.attrTypes = metadata.attrTypes[:64]
		}
	}
	return metadata
}

func (s *Session) logEAPStage(direction eapDirection, raw []byte) {
	metadata := parseEAPMetadata(raw)
	fields := []zap.Field{logger.String("direction", string(direction))}
	if metadata.parseError != eapDiagnosticValid {
		fields = append(fields, logger.String("parse_error", string(metadata.parseError)))
	}
	if metadata.parseError != eapDiagnosticPacketError {
		fields = append(fields, logger.Int("code", int(metadata.code)), logger.Any("attr_types", metadata.attrTypes),
			logger.Int("attr_count", metadata.attrCount), logger.Bool("attr_types_truncated", metadata.attrCount > 64))
		switch metadata.code {
		case eap.CodeRequest, eap.CodeResponse:
			fields = append(fields, logger.Int("type", int(metadata.method)))
			switch metadata.method {
			case eap.TypeAKA, eap.TypeAKAPrime:
				fields = append(fields, logger.Int("subtype", int(metadata.subtype)))
			}
		case eap.CodeSuccess:
			fields = append(fields, logger.String("terminal", "eap_success"))
		case eap.CodeFailure:
			fields = append(fields, logger.String("terminal", "eap_failure"))
		}
	}
	s.Logger.Info("EAP stage", fields...)
}

func (s *Session) logSentEAP(payloads []ikev2.Payload) {
	for _, payload := range payloads {
		if packet, ok := payload.(*ikev2.EncryptedPayloadEAP); ok {
			s.logEAPStage(eapSent, packet.EAPMessage)
		}
	}
}

type akaDiagnosticResult string

const (
	akaDiagnosticSuccess     akaDiagnosticResult = "success"
	akaDiagnosticSyncFailure akaDiagnosticResult = "sync_failure"
	akaDiagnosticFailure     akaDiagnosticResult = "failure"
)

func (s *Session) calculateAKAWithDiagnostics(rand, autn []byte) (res, ck, ik, auts []byte, err error) {
	s.Logger.Info("SIM AKA", logger.String("phase", "invoke"), logger.Bool("invoked", true))
	res, ck, ik, auts, err = s.cfg.SIM.CalculateAKA(rand, autn)
	result := akaDiagnosticSuccess
	switch {
	case errors.Is(err, sim.ErrSyncFailure):
		result = akaDiagnosticSyncFailure
	case err != nil:
		result = akaDiagnosticFailure
	}
	s.Logger.Info("SIM AKA", logger.String("phase", "result"), logger.Bool("invoked", true), logger.String("result", string(result)))
	return
}
