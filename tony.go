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

type authHandler interface {
	Authenticate(Request) Response
}

type Authenticator struct {
	authHandler authHandler
}

type AuthenticatorInternal struct {
	authHandlers []authHandler
}

type Throttler struct {
	authHandler authHandler
	delayCache  *cache2go.CacheTable
	baseDelay   int
	maxDelay    int
}

var cacheNameCounter uint64

func NewAuthenticator(authHandlers []authHandler) *Authenticator {
	atomic.AddUint64(&cacheNameCounter, 1)
	cache := cache2go.Cache(fmt.Sprintf("delayCache-%v", cacheNameCounter))

	return &Authenticator{
		authHandler: &Throttler{
			authHandler: &AuthenticatorInternal{
				authHandlers: authHandlers,
			},
			delayCache: cache,
			baseDelay:  2,
			maxDelay:   16,
		},
	}
}

func (a *Authenticator) Authenticate(request Request) Response {
	return a.authHandler.Authenticate(request)
}

func (a *AuthenticatorInternal) Authenticate(request Request) Response {
	for _, authHandler := range a.authHandlers {
		response := authHandler.Authenticate(request)
		if response.AuthStatus == "OK" {
			return response
		}
	}

	return Response{AuthStatus: "Invalid username or password"}
}

func (t *Throttler) Authenticate(request Request) Response {
	response := t.authHandler.Authenticate(request)

	if response.AuthStatus == "OK" {
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
