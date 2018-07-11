package tony

import "testing"

func TestAuthentication(t *testing.T) {
	// given
	h := func(r *Request) *Response {
		if r.AuthPass == "valid-pass" {
			return &Response{
				AuthStatus: "OK",
				AuthServer: "www.example.com",
				AuthPort:   143,
			}
		}

		return &Response{AuthStatus: "Invalid username or password"}
	}

	a := NewAuthenticator([]authHandler{h})

	// when, then
	test(t, a,
		req(Plain, "user", "valid-pass", IMAP, "192.168.0.1"),
		res("OK", 0, "www.example.com", 143))

	test(t, a,
		req(Plain, "user", "invalid-pass", IMAP, "192.168.0.1"),
		res("Invalid username or password", 2, "", 0))
}

func TestClientIPDelay(t *testing.T) {
	// given
	h := func(r *Request) *Response {
		if r.AuthPass == "valid-pass" {
			return &Response{
				AuthStatus: "OK",
				AuthServer: "www.example.com",
				AuthPort:   143,
			}
		}

		return &Response{AuthStatus: "Invalid username or password"}
	}

	a := NewAuthenticator([]authHandler{h})

	// when, then
	test(t, a,
		req(Plain, "user", "invalid-pass", IMAP, "192.168.0.1"),
		res("Invalid username or password", 2, "", 0))

	// Delay gets increased
	test(t, a,
		req(Plain, "user", "invalid-pass", IMAP, "192.168.0.1"),
		res("Invalid username or password", 4, "", 0))

	// Successful login is not penalized
	test(t, a,
		req(Plain, "user", "valid-pass", IMAP, "192.168.0.1"),
		res("OK", 0, "www.example.com", 143))

	// Successful login resets delay
	test(t, a,
		req(Plain, "user", "invalid-pass", IMAP, "192.168.0.1"),
		res("Invalid username or password", 2, "", 0))
}

func TestDelayShouldOnlyAffectOneClientIP(t *testing.T) {
	// given
	h := func(r *Request) *Response {
		if r.AuthPass == "valid-pass" {
			return &Response{
				AuthStatus: "OK",
				AuthServer: "www.example.com",
				AuthPort:   143,
			}
		}

		return &Response{AuthStatus: "Invalid username or password"}
	}

	a := NewAuthenticator([]authHandler{h})

	// when
	test(t, a,
		req(Plain, "user", "invalid-pass", IMAP, "192.168.0.1"),
		res("Invalid username or password", 2, "", 0))

	// then
	// delay for second clientIP starts at baseDelay again
	test(t, a,
		req(Plain, "user", "invalid-pass", IMAP, "192.168.0.2"),
		res("Invalid username or password", 2, "", 0))
}

func TestMaxDelayIsCapped(t *testing.T) {
	// given
	h := func(r *Request) *Response {
		if r.AuthPass == "valid-pass" {
			return &Response{
				AuthStatus: "OK",
				AuthServer: "www.example.com",
				AuthPort:   143,
			}
		}

		return &Response{AuthStatus: "Invalid username or password"}
	}

	a := NewAuthenticator([]authHandler{h})

	// when
	for i := 0; i < 20; i++ {
		auth(t, a, req(Plain, "user", "invalid-pass", IMAP, "192.168.0.1"))
	}

	// then
	test(t, a,
		req(Plain, "user", "invalid-pass", IMAP, "192.168.0.1"),
		res("Invalid username or password", 16, "", 0))
}

func TestEachAuthenticatorUsesItsOwnCache(t *testing.T) {
	// given
	h := func(r *Request) *Response {
		if r.AuthPass == "valid-pass" {
			return &Response{
				AuthStatus: "OK",
				AuthServer: "www.example.com",
				AuthPort:   143,
			}
		}

		return &Response{AuthStatus: "Invalid username or password"}
	}

	a := NewAuthenticator([]authHandler{h})
	b := NewAuthenticator([]authHandler{h})

	// when
	auth(t, a, req(Plain, "user", "invalid-pass", IMAP, "192.168.0.1"))
	auth(t, a, req(Plain, "user", "invalid-pass", IMAP, "192.168.0.1"))
	auth(t, a, req(Plain, "user", "invalid-pass", IMAP, "192.168.0.1"))

	test(t, b,
		req(Plain, "user", "invalid-pass", IMAP, "192.168.0.1"),
		res("Invalid username or password", 2, "", 0))
}

func TestMultipleAuthHandlers(t *testing.T) {
	// given
	h1 := func(r *Request) *Response {
		if r.AuthPass == "valid-pass1" {
			return &Response{
				AuthStatus: "OK",
				AuthServer: "www.example1.com",
				AuthPort:   1143,
			}
		}

		return &Response{AuthStatus: "Invalid username or password 1"}
	}

	h2 := func(r *Request) *Response {
		if r.AuthPass == "valid-pass2" {
			return &Response{
				AuthStatus: "OK",
				AuthServer: "www.example2.com",
				AuthPort:   2143,
			}
		}

		return &Response{AuthStatus: "Invalid username or password 2"}
	}

	// when
	a := NewAuthenticator([]authHandler{h1, h2})

	// then
	test(t, a,
		req(Plain, "user", "valid-pass1", IMAP, "192.168.0.1"),
		res("OK", 0, "www.example1.com", 1143))

	test(t, a,
		req(Plain, "user", "valid-pass2", IMAP, "192.168.0.1"),
		res("OK", 0, "www.example2.com", 2143))
}

// TODO different backend servers

func test(t *testing.T, authenticator *Authenticator, request Request, expected Response) {
	response := auth(t, authenticator, request)

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

func auth(t *testing.T, authenticator *Authenticator, request Request) Response {
	response, err := authenticator.Authenticate(&request)
	if err != nil {
		t.Fatal(err)
	}
	return *response
}

func res(status string, wait int, server string, port int) Response {
	return Response{
		AuthStatus: status,
		AuthWait:   wait,
		AuthServer: server,
		AuthPort:   port,
	}
}
