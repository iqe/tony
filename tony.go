package tony

import (
	"fmt"
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
	authServer  string
	authPort    int
	authHandler authHandler
	delayCache  *cache2go.CacheTable
	baseDelay   int
}

type authHandler (func(username string, password string) bool)

var cacheNameCounter uint64

func NewAuthenticator(authServer string, authPort int, authHandler authHandler) *Authenticator {
	atomic.AddUint64(&cacheNameCounter, 1)
	cache := cache2go.Cache(fmt.Sprintf("delayCache-%v", cacheNameCounter))

	return &Authenticator{authServer: authServer, authPort: authPort, authHandler: authHandler, delayCache: cache, baseDelay: 2}
}

func (a *Authenticator) Authenticate(request *Request) (*Response, error) {
	authenticated := a.authHandler(request.AuthUser, request.AuthPass)

	if authenticated {
		a.resetDelay(request.AuthUser)
		return &Response{
			AuthStatus: "OK",
			AuthServer: a.authServer,
			AuthPort:   a.authPort,
		}, nil
	}

	delay := a.calculateDelay(request.AuthUser)
	delay = a.calculateDelay(request.ClientIP)

	return &Response{
		AuthStatus: "Invalid username or password",
		AuthWait:   delay,
	}, nil
}

func (a *Authenticator) calculateDelay(key string) int {
	delay := a.baseDelay

	res, err := a.delayCache.Value(key)
	if err == nil {
		delay = res.Data().(int)
	}

	a.delayCache.Add(key, 60*time.Second, delay*2)

	return delay
}

func (a *Authenticator) resetDelay(key string) {
	a.delayCache.Delete(key)
}
