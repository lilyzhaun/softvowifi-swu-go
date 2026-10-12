package swu

import (
	"fmt"
	"strings"

	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/logger"
	"go.uber.org/zap"
)

const maxInitNotifyHints = 4

func (s *Session) recordInitNotifyHint(hint ikev2.InitNotifyHintError) {
	s.initHintMu.Lock()
	for _, prior := range s.initHints {
		if prior.NotifyType == hint.NotifyType {
			s.initHintMu.Unlock()
			return
		}
	}
	if len(s.initHints) == maxInitNotifyHints {
		s.initHintMu.Unlock()
		return
	}
	s.initHints = append(s.initHints, hint)
	s.initHintMu.Unlock()
	fields := []zap.Field{logger.Bool("authenticated", false), logger.Int("notifyType", int(hint.NotifyType)), logger.Int("dataLen", hint.DataLen)}
	if hint.NotifyType == ikev2.INVALID_KE_PAYLOAD {
		fields = append(fields, logger.Int("suggestedDHGroup", int(hint.SuggestedDHGroup)))
	}
	s.Logger.Info("IKE_SA_INIT unauthenticated notification hint", fields...)
}

func (s *Session) initWindowTimeout() error {
	s.initHintMu.Lock()
	defer s.initHintMu.Unlock()
	if len(s.initHints) == 0 {
		return ErrWindowTimeout
	}
	details := make([]string, 0, len(s.initHints))
	for _, hint := range s.initHints {
		details = append(details, hint.Error())
	}
	return fmt.Errorf("%w; diagnostic hints: %s", ErrWindowTimeout, strings.Join(details, "; "))
}
