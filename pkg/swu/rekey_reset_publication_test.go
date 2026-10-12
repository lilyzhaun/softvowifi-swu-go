package swu

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestRekeyResetChannelsExistBeforeControlPublication(t *testing.T) {
	s := NewSession(&Config{}, zap.NewNop())
	if s.rekeyResetCh == nil || s.childRekeyResetCh == nil {
		t.Fatal("control requests can see missing reset channels before timers start")
	}
	ike, child := s.rekeyResetCh, s.childRekeyResetCh
	s.ctx, s.cancel = context.WithCancel(t.Context())
	defer s.cancel()
	s.startIKESARekeyTimer(time.Hour)
	s.startChildSARekeyTimer(time.Hour)
	if s.rekeyResetCh != ike || s.childRekeyResetCh != child {
		t.Fatal("timers replaced channels visible to the running dispatcher")
	}
}
