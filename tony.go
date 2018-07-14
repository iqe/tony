package tony

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
	With(next AuthHandler) AuthHandler
}
