package swu

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func requireWindowClosed(t *testing.T, completion <-chan []byte) {
	t.Helper()
	select {
	case _, open := <-completion:
		if open {
			t.Fatal("request completed with a response instead of closing")
		}
	default:
		t.Fatal("request channel is still open")
	}
}

func awaitWindowClosed(t *testing.T, completion <-chan []byte) {
	t.Helper()
	select {
	case _, open := <-completion:
		if open {
			t.Fatal("canceled request delivered a response")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled request was not released")
	}
}

func windowTestResponse(id uint32) []byte {
	return (&ikev2.IKEHeader{Version: 0x20, ExchangeType: ikev2.INFORMATIONAL,
		Flags: ikev2.FlagResponse, MessageID: id, Length: 28}).Encode()
}

func requireWindowResponse(t *testing.T, completion <-chan []byte, id uint32) {
	t.Helper()
	select {
	case response, open := <-completion:
		if !open || !bytes.Equal(response, windowTestResponse(id)) {
			t.Fatalf("response = %v, open = %v", response, open)
		}
	default:
		t.Fatal("response missing")
	}
	select {
	case <-completion:
		t.Fatal("successful channel changed its single-response contract")
	default:
	}
}

func requireWindowEmpty(t *testing.T, manager *TaskManager) {
	t.Helper()
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.pending) != 0 || len(manager.queue) != 0 {
		t.Fatalf("retained requests: pending=%d queue=%d", len(manager.pending), len(manager.queue))
	}
}

func TestWindowLifecycle_rejectsAdmission_whenLoopDrained(t *testing.T) {
	for _, mode := range []string{"stop", "parent"} {
		t.Run(mode, func(t *testing.T) {
			// Given
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			sent := make(chan struct{}, 8)
			manager := NewTaskManager(parent, &RetryConfig{InitialTimeout: time.Hour}, 1, func([][]byte) error {
				sent <- struct{}{}
				return nil
			})
			defer manager.Stop()
			pending := manager.EnqueueRequest(1, 0, nil, nil)
			queued := manager.EnqueueRequest(2, 0, nil, nil)
			switch mode {
			case "stop":
				manager.Stop()
			case "parent":
				cancel()
			}
			awaitWindowClosed(t, pending)
			awaitWindowClosed(t, queued)
			requireWindowEmpty(t, manager)

			// When
			incoming := manager.EnqueueRequest(3, 0, nil, nil)

			// Then
			requireWindowClosed(t, incoming)
			requireWindowEmpty(t, manager)
			manager.Stop()
			manager.Stop()
			if len(sent) != 1 || manager.HandleResponse(1, []byte{42}) {
				t.Fatal("stopped manager sent or accepted more work")
			}
		})
	}
}

func TestWindowLifecycle_rejectsAdmission_whenParentAlreadyCanceled(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	sent := make(chan struct{}, 1)
	manager := NewTaskManager(parent, nil, 1, func([][]byte) error {
		sent <- struct{}{}
		return nil
	})
	defer manager.Stop()

	incoming := manager.EnqueueRequest(1, 0, nil, nil)

	requireWindowClosed(t, incoming)
	if len(sent) != 0 {
		t.Fatal("canceled admission sent a packet")
	}
}

func TestWindowLifecycle_preservesOwner_whenDuplicateID(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		window int
		queued bool
	}{{"pending_spare", 2, false}, {"pending_full", 1, false}, {"queued", 1, true}} {
		t.Run(scenario.name, func(t *testing.T) {
			// Given
			sent := make(chan struct{}, 8)
			manager := NewTaskManager(context.Background(), &RetryConfig{InitialTimeout: time.Hour}, scenario.window, func([][]byte) error {
				sent <- struct{}{}
				return nil
			})
			defer manager.Stop()
			if scenario.queued {
				manager.EnqueueRequest(1, ikev2.INFORMATIONAL, nil, nil)
			}
			original := manager.EnqueueRequest(7, ikev2.INFORMATIONAL, nil, nil)

			// When
			duplicate := manager.EnqueueRequest(7, 0, nil, nil)

			// Then
			requireWindowClosed(t, duplicate)
			if len(sent) != 1 {
				t.Fatal("duplicate sent a second request")
			}
			if scenario.queued && !manager.HandleResponse(1, windowTestResponse(1)) {
				t.Fatal("blocking request lost its owner")
			}
			if !manager.HandleResponse(7, windowTestResponse(7)) {
				t.Fatal("original request lost its owner")
			}
			requireWindowResponse(t, original, 7)
			reused := manager.EnqueueRequest(7, ikev2.INFORMATIONAL, nil, nil)
			if !manager.HandleResponse(7, windowTestResponse(7)) {
				t.Fatal("completed ID could not be reused")
			}
			requireWindowResponse(t, reused, 7)
			wantSends := 2
			if scenario.queued {
				wantSends++
			}
			if len(sent) != wantSends {
				t.Fatalf("sends = %d, want %d", len(sent), wantSends)
			}
			requireWindowEmpty(t, manager)
		})
	}
}

func TestWindowLifecycle_releasesRequests_whenCancelRacesAdmissionAndResponse(t *testing.T) {
	for range 64 {
		// Given
		parent, cancel := context.WithCancel(context.Background())
		manager := NewTaskManager(parent, &RetryConfig{InitialTimeout: time.Hour}, 1, func([][]byte) error { return nil })
		pending := manager.EnqueueRequest(1, ikev2.INFORMATIONAL, nil, nil)
		queued := manager.EnqueueRequest(2, 0, nil, nil)
		var incoming <-chan []byte
		var accepted bool
		start, finished := make(chan struct{}), make(chan struct{})
		var workers sync.WaitGroup
		workers.Add(4)
		for _, action := range []func(){manager.Stop, cancel,
			func() { incoming = manager.EnqueueRequest(3, 0, nil, nil) },
			func() { accepted = manager.HandleResponse(1, windowTestResponse(1)) },
		} {
			go func() { defer workers.Done(); <-start; action() }()
		}
		go func() { workers.Wait(); close(finished) }()

		// When
		close(start)

		// Then
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			cancel()
			t.Fatal("concurrent calls did not return")
		}
		if accepted {
			requireWindowResponse(t, pending, 1)
		} else {
			awaitWindowClosed(t, pending)
		}
		awaitWindowClosed(t, queued)
		awaitWindowClosed(t, incoming)
		requireWindowEmpty(t, manager)
		manager.Stop()
		if manager.HandleResponse(1, []byte{42}) {
			t.Fatal("response accepted after cancellation")
		}
	}
}

func TestWindowLifecycle_stopReturns_whenCalledInsideSend(t *testing.T) {
	var manager *TaskManager
	manager = NewTaskManager(context.Background(), &RetryConfig{InitialTimeout: time.Hour}, 1, func([][]byte) error {
		manager.Stop()
		return nil
	})
	defer manager.Stop()
	returned := make(chan (<-chan []byte), 1)

	go func() { returned <- manager.EnqueueRequest(1, 0, nil, nil) }()

	select {
	case completion := <-returned:
		awaitWindowClosed(t, completion)
		requireWindowEmpty(t, manager)
	case <-time.After(5 * time.Second):
		t.Fatal("Stop deadlocked inside send callback")
	}
}
