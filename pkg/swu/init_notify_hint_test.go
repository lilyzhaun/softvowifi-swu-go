package swu

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestInitNotifyHintPreservesPendingOfferAndEndpoint(t *testing.T) {
	session, valid := initSelectionFixture(t)
	core, logs := observer.New(zapcore.DebugLevel)
	session.Logger = zap.New(core)
	offered := bytes.Clone(session.msgBuffer)
	manager, sent := newIdleWindow(t, 1)
	manager.responseValidator = session.validateWindowResponse
	session.taskMgr = manager
	completed := manager.EnqueueRequest(0, ikev2.IKE_SA_INIT, nil, [][]byte{offered})
	before := *manager.pending[0]
	commits := 0
	raw := initHintWire(session.SPIi, 17, []byte{0, 19})
	for count := 0; count < 3; count++ {
		session.dispatchReceivedIKE(raw, func() error { commits++; return nil })
	}
	if len(manager.pending) != 1 || !reflect.DeepEqual(before, *manager.pending[0]) || commits != 0 || session.SPIr != 0 || session.Keys != nil {
		t.Fatal("unauthenticated hint changed pending, endpoint, budget or SA")
	}
	select {
	case <-completed:
		t.Fatal("hint completed the original transaction")
	default:
	}
	if len(sent) != 1 {
		t.Fatal("hint changed the original transmission budget")
	}
	if packets := <-sent; len(packets) != 1 || !bytes.Equal(packets[0], offered) {
		t.Fatal("hint changed the original offer")
	}
	entries := logs.FilterMessage("IKE_SA_INIT unauthenticated notification hint").All()
	if len(entries) != 1 {
		t.Fatalf("bounded public hint count=%d, want 1", len(entries))
	}
	if len(entries) == 1 {
		fields := entries[0].ContextMap()
		if fields["authenticated"] != false || fields["notifyType"] != int64(17) || fields["dataLen"] != int64(2) || fields["suggestedDHGroup"] != int64(19) {
			t.Fatal("hint lacks unauthenticated public metadata")
		}
		if strings.Contains(entries[0].Message, "192.0.2.") {
			t.Fatal("hint exposed endpoint data")
		}
	}
	response, err := valid.Encode()
	if err != nil {
		t.Fatal(err)
	}
	session.dispatchReceivedIKE(response, func() error { commits++; return nil })
	select {
	case received := <-completed:
		if !bytes.Equal(received, response) {
			t.Fatal("valid response was replaced by an advisory")
		}
		if err := session.handleIKESAInitResp(received, offered); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("original transaction could not complete after an advisory")
	}
	if commits != 1 || len(manager.pending) != 0 || session.Keys == nil || session.ikeDHID != 14 {
		t.Fatal("valid original-offer response did not install the original DH selection")
	}
}

// Independent wire framing: no production Notify encoder produces these bytes.
func initHintWire(spii uint64, notifyType uint16, data []byte) []byte {
	raw := make([]byte, 36+len(data))
	binary.BigEndian.PutUint64(raw[:8], spii)
	raw[16], raw[17], raw[18], raw[19] = 41, 0x20, 34, 0x20
	binary.BigEndian.PutUint32(raw[24:28], uint32(len(raw)))
	binary.BigEndian.PutUint16(raw[30:32], uint16(len(raw)-28))
	binary.BigEndian.PutUint16(raw[34:36], notifyType)
	copy(raw[36:], data)
	return raw
}

func TestInitNotifyHintRejectsUnboundMalformedAndNonSinglePayloads(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"SPIi", func(b []byte) []byte { b[0] ^= 1; return b }},
		{"MID", func(b []byte) []byte { b[23] = 1; return b }},
		{"exchange", func(b []byte) []byte { b[18] = 35; return b }},
		{"major", func(b []byte) []byte { b[17] = 0x30; return b }},
		{"initiator", func(b []byte) []byte { b[19] |= 8; return b }},
		{"request", func(b []byte) []byte { b[19] = 0; return b }},
		{"header length", func(b []byte) []byte { b[27]--; return b }},
		{"truncated", func(b []byte) []byte { return b[:len(b)-1] }},
		{"notify protocol with SPI", func(b []byte) []byte { b[32] = 1; b[33] = 1; return b }},
		{"notify SPI", func(b []byte) []byte { b[33] = 1; return b }},
		{"KE length", func(b []byte) []byte { b = append(b, 0); b[31]++; b[27]++; return b }},
		{"dangling next", func(b []byte) []byte { b[28] = 41; return b }},
		{"unknown noncritical suffix", func(b []byte) []byte { b[28] = 250; b = append(b, 0, 0, 0, 4); b[27] += 4; return b }},
		{"duplicate notify", func(b []byte) []byte {
			tail := bytes.Clone(b[28:])
			b[28] = 41
			b = append(b, tail...)
			b[27] += byte(len(tail))
			return b
		}},
		{"status notify", func(b []byte) []byte { binary.BigEndian.PutUint16(b[34:36], 16384); return b }},
		{"reserved zero", func(b []byte) []byte { b[35] = 0; return b }},
	} {
		t.Run(test.name, func(t *testing.T) {
			session := newInitTestSession("")
			core, logs := observer.New(zapcore.DebugLevel)
			session.Logger = zap.New(core)
			offered, err := session.buildIKESAInitPacket()
			if err != nil {
				t.Fatal(err)
			}
			manager, _ := newIdleWindow(t, 1)
			manager.responseValidator = session.validateWindowResponse
			session.taskMgr = manager
			completed := manager.EnqueueRequest(0, ikev2.IKE_SA_INIT, nil, [][]byte{offered})
			raw := test.mutate(initHintWire(session.SPIi, 17, []byte{0, 19}))
			_, decodeErr := ikev2.DecodeInitResponse(raw, offered)
			var hint *ikev2.InitNotifyHintError
			if decodeErr == nil || errors.As(decodeErr, &hint) {
				t.Fatal("malformed or non-single reply became a diagnostic hint")
			}
			session.dispatchReceivedIKE(raw, func() error { t.Error("invalid hint committed the endpoint"); return nil })
			if logs.FilterMessage("IKE_SA_INIT unauthenticated notification hint").Len() != 0 || len(manager.pending) != 1 {
				t.Fatal("invalid input consumed hint capacity or pending")
			}
			select {
			case <-completed:
				t.Fatal("invalid reply completed transaction")
			default:
			}
		})
	}
}

func TestInitNotifyHintsAreBoundedByTypeAndKeepOnlyPublicMetadata(t *testing.T) {
	session := newInitTestSession("")
	core, logs := observer.New(zapcore.DebugLevel)
	session.Logger = zap.New(core)
	offered, err := session.buildIKESAInitPacket()
	if err != nil {
		t.Fatal(err)
	}
	manager, _ := newIdleWindow(t, 1)
	manager.responseValidator = session.validateWindowResponse
	session.taskMgr = manager
	manager.EnqueueRequest(0, ikev2.IKE_SA_INIT, nil, [][]byte{offered})
	const privateData = "synthetic-private-notify-payload"
	for _, code := range []uint16{17, 17, 5, 7, 24, 43, 44} {
		data := []byte(privateData)
		if code == 17 {
			data = []byte{0, 19}
		}
		session.dispatchReceivedIKE(initHintWire(session.SPIi, code, data), nil)
	}
	entries := logs.FilterMessage("IKE_SA_INIT unauthenticated notification hint").All()
	if len(entries) != 4 {
		t.Fatalf("bounded hint count=%d, want 4", len(entries))
	}
	for _, entry := range entries {
		for key := range entry.ContextMap() {
			if key != "authenticated" && key != "notifyType" && key != "dataLen" && key != "suggestedDHGroup" {
				t.Fatalf("unexpected diagnostic field %s", key)
			}
		}
	}
	err = session.initWindowTimeout()
	if !errors.Is(err, ErrWindowTimeout) || !strings.Contains(err.Error(), "unauthenticated") || !strings.Contains(err.Error(), "suggestedDHGroup=19") || strings.Contains(err.Error(), privateData) || strings.Contains(err.Error(), "type=43 ") {
		t.Fatalf("timeout lost its bounded safe metadata or error identity: %v", err)
	}
	if got := newInitTestSession("").initWindowTimeout(); got != ErrWindowTimeout {
		t.Fatal("unhinted timeout identity changed")
	}
}
