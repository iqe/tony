package tony

import (
	"fmt"
	"math"
	"sync/atomic"
	"time"

	"github.com/muesli/cache2go"
)

type Request struct {
	AuthMethod   Method
	AuthUser     string
	AuthPass     string
	AuthProtocol Protocol
	ClientIP     string
}

type Method int

const (
	OtherMethod Method = iota
	Plain
	CramMD5
	DigestMD5
)

type Protocol int

const (
	OtherProtocol Protocol = iota
	IMAP
	POP3
	SMTP
)

const AuthStatusOK = "OK"

type Response struct {
	AuthStatus string
	AuthWait   int
	AuthServer string
	AuthPort   int
}

type AuthHandler interface {
	Authenticate(Request) Response
}

type Tony struct {
	AuthHandler AuthHandler
}

type Looper struct {
	AuthHandlers []AuthHandler
}

type Throttler struct {
	AuthHandler AuthHandler
	delayCache  *cache2go.CacheTable
	baseDelay   int
	maxDelay    int
}

type MethodGate struct {
	AuthHandler    AuthHandler
	allowedMethods []Method
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

func NewLooper() *Looper {
	return &Looper{}
}

func NewMethodGate(allowedMethods ...Method) *MethodGate {
	return &MethodGate{allowedMethods: allowedMethods}
}

func (t *Tony) Authenticate(request Request) Response {
	return t.AuthHandler.Authenticate(request)
}

func (l *Looper) Authenticate(request Request) Response {
	for _, AuthHandler := range l.AuthHandlers {
		response := AuthHandler.Authenticate(request)
		if response.AuthStatus == AuthStatusOK {
			return response
		}
	}

	return Response{AuthStatus: "Invalid username or password"}
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

func (m *MethodGate) Authenticate(request Request) Response {
	for _, method := range m.allowedMethods {
		if request.AuthMethod == method {
			return m.AuthHandler.Authenticate(request)
		}
	}

	return Response{AuthStatus: "Authentication method not supported"}
}
