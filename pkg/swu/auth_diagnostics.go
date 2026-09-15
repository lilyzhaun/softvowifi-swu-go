package swu

import (
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/logger"
)

type ikeAuthMetadataPhase string

const (
	ikeAuthPhaseEAPLoop       ikeAuthMetadataPhase = "eap_loop"
	ikeAuthPhaseFinal         ikeAuthMetadataPhase = "final"
	ikeAuthMetadataMaxRecords                      = 64
)

type ikeAuthNotifyRecord struct {
	Type       int `json:"type"`
	Protocol   int `json:"protocol"`
	SPILength  int `json:"spi_length"`
	DataLength int `json:"data_length"`
}

func (s *Session) logIKEAuthMetadata(phase ikeAuthMetadataPhase, payloads []ikev2.Payload) {
	types := make([]int, 0, len(payloads))
	notifies := make([]ikeAuthNotifyRecord, 0)
	for _, payload := range payloads {
		types = append(types, int(payload.Type()))
		notify, ok := payload.(*ikev2.EncryptedPayloadNotify)
		if !ok {
			continue
		}
		notifies = append(notifies, ikeAuthNotifyRecord{
			Type:       int(notify.NotifyType),
			Protocol:   int(notify.ProtocolID),
			SPILength:  len(notify.SPI),
			DataLength: len(notify.NotifyData),
		})
	}
	typeCount, notifyCount := len(types), len(notifies)
	typesTruncated := typeCount > ikeAuthMetadataMaxRecords
	notifiesTruncated := notifyCount > ikeAuthMetadataMaxRecords
	if typesTruncated {
		types = types[:ikeAuthMetadataMaxRecords]
	}
	if notifiesTruncated {
		notifies = notifies[:ikeAuthMetadataMaxRecords]
	}
	s.Logger.Info("IKE_AUTH metadata",
		logger.String("direction", "received"),
		logger.String("phase", string(phase)),
		logger.Any("parsed_payload_types", types),
		logger.Int("parsed_payload_count", typeCount),
		logger.Bool("parsed_payload_types_truncated", typesTruncated),
		logger.Any("notifications", notifies),
		logger.Int("notification_count", notifyCount),
		logger.Bool("notifications_truncated", notifiesTruncated),
		logger.Bool("protected_packet_decoded", true),
	)
}
