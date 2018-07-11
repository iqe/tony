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
	Plain Method = iota
	Apop
	CramMD5
	External
)

type Protocol int

const (
	IMAP Protocol = iota
	POP3
	SMTP
)

type Response struct {
	AuthStatus string
	AuthWait   int
	AuthServer string
	AuthPort   int
}

type Authenticator struct {
	authHandler authHandler
	delayCache  *cache2go.CacheTable
	baseDelay   int
	maxDelay    int
}

type authHandler (func(request *Request) *Response)

var cacheNameCounter uint64

func NewAuthenticator(authHandler authHandler) *Authenticator {
	atomic.AddUint64(&cacheNameCounter, 1)
	cache := cache2go.Cache(fmt.Sprintf("delayCache-%v", cacheNameCounter))

	return &Authenticator{
		authHandler: authHandler,
		delayCache:  cache,
		baseDelay:   2,
		maxDelay:    16,
	}
}

func (a *Authenticator) Authenticate(request *Request) (*Response, error) {
	response := a.authHandler(request)

	if response.AuthStatus == "OK" {
		a.resetDelay(request.ClientIP)
	} else {
		delay := a.updateDelay(request.ClientIP)
		response.AuthWait = delay
	}

	return response, nil
}

func (a *Authenticator) updateDelay(key string) int {
	delay := a.baseDelay

	res, err := a.delayCache.Value(key)
	if err == nil {
		delay = res.Data().(int)
	}

	newDelay := int(math.Min(float64(delay*2), float64(a.maxDelay)))
	a.delayCache.Add(key, 60*time.Second, newDelay)

	return delay
}

func (a *Authenticator) resetDelay(key string) {
	a.delayCache.Delete(key)
}
