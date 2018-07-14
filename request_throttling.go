package tony

import (
	"fmt"
	"math"
	"sync/atomic"
	"time"

	"github.com/muesli/cache2go"
)

type requestThrottlingHandler struct {
	next       AuthHandler
	delayCache *cache2go.CacheTable
	baseDelay  int
	maxDelay   int
}

var cacheNameCounter uint64

func RequestThrottling(baseDelay int, maxDelay int, next AuthHandler) AuthHandler {
	atomic.AddUint64(&cacheNameCounter, 1)
	cache := cache2go.Cache(fmt.Sprintf("delayCache-%v", cacheNameCounter))

	return &requestThrottlingHandler{
		delayCache: cache,
		baseDelay:  baseDelay,
		maxDelay:   maxDelay,
		next:       next,
	}
}

func (h *requestThrottlingHandler) Authenticate(request Request) Response {
	response := h.next.Authenticate(request)

	if response.AuthStatus == authStatusOK {
		h.resetDelay(request.ClientIP)
	} else {
		delay := h.updateDelay(request.ClientIP)
		response.AuthWait = delay
	}

	return response
}

func (h *requestThrottlingHandler) updateDelay(key string) int {
	delay := h.baseDelay

	res, err := h.delayCache.Value(key)
	if err == nil {
		delay = res.Data().(int)
	}

	newDelay := int(math.Min(float64(delay*2), float64(h.maxDelay)))
	h.delayCache.Add(key, 60*time.Second, newDelay)

	return delay
}

func (h *requestThrottlingHandler) resetDelay(key string) {
	h.delayCache.Delete(key)
}
