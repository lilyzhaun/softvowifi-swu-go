//go:build go1.25

package swu

import (
	"bytes"
	"context"
	"testing"
	"testing/synctest"
	"time"
)

func TestChildPFSLocalRetransmissionKeepsIdenticalDHAndWire(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, pipe := childRekeySession(t)
		s.cancel()
		s.taskMgr.Stop()
		s.ctx, s.cancel = context.WithCancel(t.Context())
		defer s.cancel()
		s.taskMgr = NewTaskManager(s.ctx, nil, 1, func(packets [][]byte) error {
			for _, packet := range packets {
				if err := pipe.SendIKE(packet); err != nil {
					return err
				}
			}
			return nil
		})
		defer s.taskMgr.Stop()
		s.cfg.ChildPFSGroup = 14
		kernel := newRekeyKernel()
		_, _, _, err := exerciseChildPFS(t, s, func() error { return s.rekeyChildSA(kernel) }, nil, func(first []byte) {
			// Retain the production four-second retry clock; synctest advances
			// time rather than weakening it or waiting in wall-clock time.
			time.Sleep(4 * time.Second)
			synctest.Wait()
			if second := <-pipe.sent; !bytes.Equal(first, second) || len(kernel.calls) != 0 {
				t.Fatal("retry regenerated DH/nonce/ciphertext or installed before response")
			}
		})
		if err != nil || len(kernel.adds) != 2 {
			t.Fatal("retried PFS exchange did not commit exactly once")
		}
	})
}
