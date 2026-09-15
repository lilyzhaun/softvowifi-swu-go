package swu

import (
	"sync"
	"testing"
	"time"
)

func TestInboundActivityTimestampSupportsConcurrentReadWrite(t *testing.T) {
	session := &Session{}
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func(offset int) {
			defer wg.Done()
			session.recordInboundActivity(time.Unix(int64(offset), 0))
		}(i)
		go func() {
			defer wg.Done()
			_ = session.inboundIdle(time.Now())
		}()
	}

	wg.Wait()
}
