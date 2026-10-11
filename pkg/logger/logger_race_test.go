package logger

import (
	"sync"
	"testing"

	"go.uber.org/zap"
)

func resetGlobalLoggerForTest(t *testing.T) {
	t.Helper()
	globalMu.Lock()
	previousLogger, previousSugar := globalLogger, globalSugar
	globalLogger, globalSugar, once = nil, nil, sync.Once{}
	globalMu.Unlock()
	t.Cleanup(func() {
		globalMu.Lock()
		globalLogger, globalSugar, once = previousLogger, previousSugar, sync.Once{}
		globalMu.Unlock()
	})
}

// The first log calls of a process may come from concurrent goroutines; the
// lazy default must be published under synchronisation. Run with -race.
func TestGet_concurrentFirstUseSharesOneLogger(t *testing.T) {
	resetGlobalLoggerForTest(t)
	const workers = 8
	results := make([]*zap.Logger, workers)
	sugars := make([]*zap.SugaredLogger, workers)
	start := make(chan struct{})
	var group sync.WaitGroup
	for index := range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			results[index] = Get()
			sugars[index] = Sugar()
			Debug("synthetic concurrent first use")
		}()
	}
	close(start)
	group.Wait()
	for index := range workers {
		if results[index] == nil || results[index] != results[0] || sugars[index] == nil || sugars[index] != sugars[0] {
			t.Fatalf("worker %d saw logger=%p sugar=%p, first saw %p/%p", index, results[index], sugars[index], results[0], sugars[0])
		}
	}
}

func TestSetLogger_concurrentWithReadersPublishesInjectedLogger(t *testing.T) {
	resetGlobalLoggerForTest(t)
	injected := zap.NewNop()
	var group sync.WaitGroup
	for range 4 {
		group.Add(2)
		go func() { defer group.Done(); SetLogger(injected) }()
		go func() { defer group.Done(); _ = Get(); _ = Sugar(); Sync() }()
	}
	group.Wait()
	SetLogger(injected)
	if Get() != injected || Sugar() == nil {
		t.Fatal("injected logger was not published")
	}
}

func TestInit_onlyFirstCallConfiguresDefault(t *testing.T) {
	resetGlobalLoggerForTest(t)
	if err := Init("debug", "json"); err != nil {
		t.Fatal(err)
	}
	first := Get()
	if err := Init("error", "console"); err != nil {
		t.Fatal(err)
	}
	if Get() != first {
		t.Fatal("second Init replaced the configured logger")
	}
}
