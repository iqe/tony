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
	authHandlers []authHandler
	delayCache   *cache2go.CacheTable
	baseDelay    int
	maxDelay     int
}

type authHandler interface {
	Authenticate(Request) Response
}

var cacheNameCounter uint64

func NewAuthenticator(authHandlers []authHandler) *Authenticator {
	atomic.AddUint64(&cacheNameCounter, 1)
	cache := cache2go.Cache(fmt.Sprintf("delayCache-%v", cacheNameCounter))

	return &Authenticator{
		authHandlers: authHandlers,
		delayCache:   cache,
		baseDelay:    2,
		maxDelay:     16,
	}
}

func (a *Authenticator) Authenticate(request Request) Response {
	var response Response
	for _, authHandler := range a.authHandlers {
		response = authHandler.Authenticate(request)
		if response.AuthStatus == "OK" {
			break
		}
	}

	if response.AuthStatus == "OK" {
		a.resetDelay(request.ClientIP)
	} else {
		delay := a.updateDelay(request.ClientIP)
		response.AuthStatus = "Invalid username or password"
		response.AuthWait = delay
	}

	return response
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
