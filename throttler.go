package tony

import (
	"fmt"
	"math"
	"sync/atomic"
	"time"

	"github.com/muesli/cache2go"
)

type throttler struct {
	next       AuthHandler
	delayCache *cache2go.CacheTable
	baseDelay  int
	maxDelay   int
}

var cacheNameCounter uint64

func NewThrottler(baseDelay int, maxDelay int) AuthHandler {
	atomic.AddUint64(&cacheNameCounter, 1)
	cache := cache2go.Cache(fmt.Sprintf("delayCache-%v", cacheNameCounter))

	return &throttler{
		delayCache: cache,
		baseDelay:  baseDelay,
		maxDelay:   maxDelay,
	}
}

func (t *throttler) With(next AuthHandler) AuthHandler {
	t.next = next
	return t
}

func (t *throttler) Authenticate(request Request) Response {
	response := t.next.Authenticate(request)

	if response.AuthStatus == authStatusOK {
		t.resetDelay(request.ClientIP)
	} else {
		delay := t.updateDelay(request.ClientIP)
		response.AuthWait = delay
	}

	return response
}

func (t *throttler) updateDelay(key string) int {
	delay := t.baseDelay

	res, err := t.delayCache.Value(key)
	if err == nil {
		delay = res.Data().(int)
	}

	newDelay := int(math.Min(float64(delay*2), float64(t.maxDelay)))
	t.delayCache.Add(key, 60*time.Second, newDelay)

	return delay
}

func (t *throttler) resetDelay(key string) {
	t.delayCache.Delete(key)
}
