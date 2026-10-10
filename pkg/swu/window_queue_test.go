package swu

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func newIdleWindow(t *testing.T, size int) (*TaskManager, chan [][]byte) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	sent := make(chan [][]byte, 32)
	manager := &TaskManager{
		ctx: ctx, cancel: cancel,
		config:     &RetryConfig{MaxRetries: 2, InitialTimeout: time.Hour, BackoffFactor: 2},
		windowSize: size, pending: make(map[uint32]*OutgoingMessage),
		wakeupCh: make(chan struct{}, 1),
		sendFunc: func(packets [][]byte) error { sent <- packets; return nil },
	}
	t.Cleanup(func() { manager.Stop(); manager.windowLoop() })
	return manager, sent
}

func requireWindowSends(t *testing.T, sent <-chan [][]byte, want [][][]byte) {
	t.Helper()
	for _, packets := range want {
		select {
		case actual := <-sent:
			if !reflect.DeepEqual(actual, packets) {
				t.Fatalf("sent %v, want %v", actual, packets)
			}
		default:
			t.Fatalf("missing send %v", packets)
		}
	}
	if len(sent) != 0 {
		t.Fatalf("unexpected extra sends: %d", len(sent))
	}
}

func TestWindowQueue_fillsEveryVacancyFIFO_whenMultipleRequestsExpire(t *testing.T) {
	// Given
	manager, sent := newIdleWindow(t, 3)
	manager.config.MaxRetries = 0
	channels := make([]<-chan []byte, 0, 7)
	for id := uint32(1); id <= 7; id++ {
		channels = append(channels, manager.EnqueueRequest(id, 0, nil, [][]byte{{byte(id)}}))
	}
	manager.mu.Lock()
	manager.pending[1].Deadline = time.Unix(1, 0)
	manager.pending[2].Deadline = time.Unix(1, 0)
	unchanged := *manager.pending[3]
	manager.mu.Unlock()

	// When
	manager.checkTimeouts()

	// Then
	requireWindowClosed(t, channels[0])
	requireWindowClosed(t, channels[1])
	requireWindowSends(t, sent, [][][]byte{{{1}}, {{2}}, {{3}}, {{4}}, {{5}}})
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.pending) != 3 || len(manager.queue) != 2 || manager.queue[0].MsgID != 6 || manager.queue[1].MsgID != 7 {
		t.Fatalf("window not refilled: pending=%d queue=%d", len(manager.pending), len(manager.queue))
	}
	if !reflect.DeepEqual(*manager.pending[3], unchanged) {
		t.Fatal("nonexpired request changed")
	}
}

func TestWindowQueue_preservesBackoffAndPackets_whenRetryDue(t *testing.T) {
	for _, limit := range []time.Duration{0, 90 * time.Minute} {
		t.Run(limit.String(), func(t *testing.T) {
			// Given
			manager, sent := newIdleWindow(t, 2)
			manager.config.MaxTimeout = limit
			packets := [][]byte{{1, 2}, {3, 4}}
			completion := manager.EnqueueRequest(1, 0, nil, packets)
			manager.EnqueueRequest(2, 0, nil, [][]byte{{2}})
			manager.EnqueueRequest(3, 0, nil, [][]byte{{3}})
			manager.mu.Lock()
			manager.pending[1].Deadline = time.Unix(1, 0)
			unchanged := *manager.pending[2]
			manager.mu.Unlock()
			before := time.Now()

			// When
			manager.checkTimeouts()

			// Then
			requireWindowSends(t, sent, [][][]byte{packets, {{2}}, packets})
			manager.mu.Lock()
			defer manager.mu.Unlock()
			want := 2 * time.Hour
			if limit > 0 {
				want = limit
			}
			request := manager.pending[1]
			if request.RetryCount != 1 || request.MaxRetries != 2 || request.NextTimeout != want || request.CompletionCh != completion {
				t.Fatalf("retry state = %+v", request)
			}
			if request.Deadline.Before(before.Add(want)) || request.Deadline.After(time.Now().Add(want)) {
				t.Fatal("retry deadline does not use the configured interval")
			}
			if !reflect.DeepEqual(*manager.pending[2], unchanged) || len(manager.queue) != 1 {
				t.Fatal("retry changed nonexpired request or admitted queued work")
			}
		})
	}
}

func TestWindowQueue_deliversOnceAndPumpsFIFO_whenResponseKnown(t *testing.T) {
	manager, sent := newIdleWindow(t, 1)
	original := manager.EnqueueRequest(1, ikev2.INFORMATIONAL, nil, [][]byte{{1}})
	queued := manager.EnqueueRequest(2, ikev2.INFORMATIONAL, nil, [][]byte{{2}})

	accepted := manager.HandleResponse(1, windowTestResponse(1))

	if !accepted {
		t.Fatal("known response rejected")
	}
	requireWindowResponse(t, original, 1)
	requireWindowSends(t, sent, [][][]byte{{{1}}, {{2}}})
	for _, id := range []uint32{1, 99} {
		if manager.HandleResponse(id, windowTestResponse(id)) {
			t.Fatal("late or unknown response accepted")
		}
	}
	if len(sent) != 0 || len(manager.pending) != 1 {
		t.Fatal("unknown response changed scheduling")
	}
	if !manager.HandleResponse(2, windowTestResponse(2)) {
		t.Fatal("queued request lost its response")
	}
	requireWindowResponse(t, queued, 2)
	requireWindowEmpty(t, manager)
}

func TestWindowQueue_rejectsWork_whenCanceledBeforeCleanup(t *testing.T) {
	for _, operation := range []string{"response", "timeout", "retry", "pump", "admission"} {
		t.Run(operation, func(t *testing.T) {
			// Given: no background loop; cancellation precedes the actual public/scheduler call.
			manager, sent := newIdleWindow(t, 1)
			pending := manager.EnqueueRequest(1, 0, nil, [][]byte{{1}})
			queued := manager.EnqueueRequest(2, 0, nil, [][]byte{{2}})
			manager.mu.Lock()
			manager.pending[1].Deadline = time.Unix(1, 0)
			manager.mu.Unlock()
			manager.Stop()

			// When
			switch operation {
			case "response":
				if manager.HandleResponse(1, []byte{42}) {
					t.Error("response accepted after cancellation")
				}
			case "timeout":
				manager.pending[1].MaxRetries = 0
				manager.checkTimeouts()
			case "retry":
				manager.checkTimeouts()
			case "pump":
				manager.mu.Lock()
				manager.windowSize = 2
				manager.pumpQueue()
				manager.mu.Unlock()
			case "admission":
				requireWindowClosed(t, manager.EnqueueRequest(3, 0, nil, nil))
			}

			// Then
			requireWindowSends(t, sent, [][][]byte{{{1}}})
			manager.windowLoop()
			requireWindowClosed(t, pending)
			requireWindowClosed(t, queued)
			requireWindowEmpty(t, manager)
		})
	}
}

func TestWindowQueue_stopsFurtherSends_whenCallbackCancels(t *testing.T) {
	for _, phase := range []string{"retry", "refill"} {
		t.Run(phase, func(t *testing.T) {
			// Given
			manager, sent := newIdleWindow(t, 3)
			channels := make([]<-chan []byte, 0, 7)
			for id := uint32(1); id <= 7; id++ {
				channels = append(channels, manager.EnqueueRequest(id, 0, nil, [][]byte{{byte(id)}}))
			}
			manager.mu.Lock()
			for _, request := range manager.pending {
				request.Deadline = time.Unix(1, 0)
				if phase == "refill" || request.MsgID == 1 {
					request.MaxRetries = 0
				}
			}
			manager.sendFunc = func(packets [][]byte) error { sent <- packets; manager.Stop(); return nil }
			manager.mu.Unlock()

			// When
			manager.checkTimeouts()

			// Then
			if len(sent) != 4 {
				t.Fatalf("sends = %d, want 3 initial + 1 callback cancellation", len(sent))
			}
			manager.windowLoop()
			for _, completion := range channels {
				requireWindowClosed(t, completion)
			}
			requireWindowEmpty(t, manager)
		})
	}
}
