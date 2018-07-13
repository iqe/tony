package tony

import (
	"fmt"
	"math"
	"sync/atomic"
	"time"

	"github.com/muesli/cache2go"
)

type Throttler struct {
	AuthHandler AuthHandler
	delayCache  *cache2go.CacheTable
	baseDelay   int
	maxDelay    int
}

var cacheNameCounter uint64

func NewThrottler(baseDelay int, maxDelay int) *Throttler {
	atomic.AddUint64(&cacheNameCounter, 1)
	cache := cache2go.Cache(fmt.Sprintf("delayCache-%v", cacheNameCounter))

	return &Throttler{
		delayCache: cache,
		baseDelay:  baseDelay,
		maxDelay:   maxDelay,
	}
}

func (t *Throttler) Authenticate(request Request) Response {
	response := t.AuthHandler.Authenticate(request)

	if response.AuthStatus == AuthStatusOK {
		t.resetDelay(request.ClientIP)
	} else {
		delay := t.updateDelay(request.ClientIP)
		response.AuthWait = delay
	}

	return response
}

func (t *Throttler) updateDelay(key string) int {
	delay := t.baseDelay

	res, err := t.delayCache.Value(key)
	if err == nil {
		delay = res.Data().(int)
	}

	newDelay := int(math.Min(float64(delay*2), float64(t.maxDelay)))
	t.delayCache.Add(key, 60*time.Second, newDelay)

	return delay
}

func (t *Throttler) resetDelay(key string) {
	t.delayCache.Delete(key)
}
