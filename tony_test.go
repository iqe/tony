package tony

import (
	"testing"
)

type testAuthHandler struct {
	validPass     string
	server        string
	port          int
	failureStatus string
}

func (h *testAuthHandler) With(next AuthHandler) AuthHandler {
	panic("Should never be called")
}

func (h *testAuthHandler) Authenticate(r Request) Response {
	if r.AuthPass == h.validPass {
		return Response{
			AuthStatus: authStatusOK,
			AuthServer: h.server,
			AuthPort:   h.port,
		}
	}

	return Response{AuthStatus: h.failureStatus}
}

func New(handlers []AuthHandler) AuthHandler {
	looper := AnyOf()
	for _, h := range handlers {
		looper.With(h)
	}

	return RequestThrottling(2, 16).With(
		AllowedMethods(Plain).With(
			looper,
		),
	)
}

func newTestAuthHandler(validPass string, server string, port int) *testAuthHandler {
	return &testAuthHandler{
		validPass:     validPass,
		server:        server,
		port:          port,
		failureStatus: "Invalid username or password (msg from handler)",
	}
}

func TestAuthentication(t *testing.T) {
	// given
	h := newTestAuthHandler("valid-pass", "www.example.com", 143)
	tony := New([]AuthHandler{h})

	// when, then
	test(t, tony,
		req(Plain, "user", "valid-pass", IMAP, "192.168.0.1"),
		res("OK", 0, "www.example.com", 143))

	test(t, tony,
		req(Plain, "user", "invalid-pass", IMAP, "192.168.0.1"),
		res("Invalid username or password", 2, "", 0))
}

func TestClientIPDelay(t *testing.T) {
	// given
	h := newTestAuthHandler("valid-pass", "www.example.com", 143)
	tony := New([]AuthHandler{h})

	// when, then
	test(t, tony,
		req(Plain, "user", "invalid-pass", IMAP, "192.168.0.1"),
		res("Invalid username or password", 2, "", 0))

	// Delay gets increased
	test(t, tony,
		req(Plain, "user", "invalid-pass", IMAP, "192.168.0.1"),
		res("Invalid username or password", 4, "", 0))

	// Successful login is not penalized
	test(t, tony,
		req(Plain, "user", "valid-pass", IMAP, "192.168.0.1"),
		res("OK", 0, "www.example.com", 143))

	// Successful login resets delay
	test(t, tony,
		req(Plain, "user", "invalid-pass", IMAP, "192.168.0.1"),
		res("Invalid username or password", 2, "", 0))
}

func TestDelayShouldOnlyAffectOneClientIP(t *testing.T) {
	// given
	h := newTestAuthHandler("valid-pass", "www.example.com", 143)
	tony := New([]AuthHandler{h})

	// when
	test(t, tony,
		req(Plain, "user", "invalid-pass", IMAP, "192.168.0.1"),
		res("Invalid username or password", 2, "", 0))

	// then
	// delay for second clientIP starts at baseDelay again
	test(t, tony,
		req(Plain, "user", "invalid-pass", IMAP, "192.168.0.2"),
		res("Invalid username or password", 2, "", 0))
}

func TestMaxDelayIsCapped(t *testing.T) {
	// given
	h := newTestAuthHandler("valid-pass", "www.example.com", 143)
	tony := New([]AuthHandler{h})

	// when
	for i := 0; i < 20; i++ {
		auth(t, tony, req(Plain, "user", "invalid-pass", IMAP, "192.168.0.1"))
	}

	// then
	test(t, tony,
		req(Plain, "user", "invalid-pass", IMAP, "192.168.0.1"),
		res("Invalid username or password", 16, "", 0))
}

func TestEachInstanceUsesItsOwnCache(t *testing.T) {
	// given
	h := newTestAuthHandler("valid-pass", "www.example.com", 143)
	tony1 := New([]AuthHandler{h})
	tony2 := New([]AuthHandler{h})

	// when
	auth(t, tony1, req(Plain, "user", "invalid-pass", IMAP, "192.168.0.1"))
	auth(t, tony1, req(Plain, "user", "invalid-pass", IMAP, "192.168.0.1"))
	auth(t, tony1, req(Plain, "user", "invalid-pass", IMAP, "192.168.0.1"))

	// delay from a does not affect b
	test(t, tony2,
		req(Plain, "user", "invalid-pass", IMAP, "192.168.0.1"),
		res("Invalid username or password", 2, "", 0))
}

func TestMultipleAuthHandlers(t *testing.T) {
	// given
	h1 := &testAuthHandler{
		validPass:     "valid-pass1",
		server:        "www.example1.com",
		port:          1143,
		failureStatus: "Invalid username or password (msg from h1)",
	}

	h2 := &testAuthHandler{
		validPass:     "valid-pass2",
		server:        "www.example2.com",
		port:          2143,
		failureStatus: "Invalid username or password (msg from h2)",
	}

	// when
	tony := New([]AuthHandler{h1, h2})

	// then
	test(t, tony,
		req(Plain, "user", "valid-pass1", IMAP, "192.168.0.1"),
		res("OK", 0, "www.example1.com", 1143))

	test(t, tony,
		req(Plain, "user", "valid-pass2", IMAP, "192.168.0.1"),
		res("OK", 0, "www.example2.com", 2143))

	test(t, tony,
		req(Plain, "user", "invalid-pass", IMAP, "192.168.0.1"),
		res("Invalid username or password", 2, "", 0))
}

func TestOnlyMethodPlainIsAllowed(t *testing.T) {
	// given
	h := newTestAuthHandler("valid-pass", "www.example.com", 143)
	tony := New([]AuthHandler{h})

	// when
	test(t, tony,
		req(CramMD5, "user", "valid-pass", IMAP, "192.168.0.1"),
		res("Authentication method not supported", 2, "", 0))
}

func test(t *testing.T, handler AuthHandler, request Request, expected Response) {
	response := auth(t, handler, request)

	if response != expected {
		t.Fatal("Request ", request, ": Expected ", expected, " got ", response)
	}
}

func req(method Method, user string, pass string, protocol Protocol, clientIP string) Request {
	return Request{
		AuthMethod:   method,
		AuthUser:     user,
		AuthPass:     pass,
		AuthProtocol: protocol,
		ClientIP:     clientIP,
	}
}

func auth(t *testing.T, h AuthHandler, request Request) Response {
	return h.Authenticate(request)
}

func res(status string, wait int, server string, port int) Response {
	return Response{
		AuthStatus: status,
		AuthWait:   wait,
		AuthServer: server,
		AuthPort:   port,
	}
}
