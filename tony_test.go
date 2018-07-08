package tony

import "testing"

func TestAuthentication(t *testing.T) {
	// given
	h := func(u string, p string) bool {
		return p == "valid-pass"
	}

	a := NewAuthenticator("www.example.com", 143, h)

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
	h := func(u string, p string) bool {
		return p == "valid-pass"
	}

	a := NewAuthenticator("www.example.com", 143, h)

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
	h := func(u string, p string) bool {
		return p == "valid-pass"
	}

	a := NewAuthenticator("www.example.com", 143, h)

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

func TestEachAuthenticatorUsesItsOwnCache(t *testing.T) {
	// given
	h := func(u string, p string) bool {
		return p == "valid-pass"
	}

	a := NewAuthenticator("www.example.com", 143, h)
	b := NewAuthenticator("www.example.com", 143, h)

	// when
	auth(t, a, req(Plain, "user", "invalid-pass", IMAP, "192.168.0.1"))
	auth(t, a, req(Plain, "user", "invalid-pass", IMAP, "192.168.0.1"))
	auth(t, a, req(Plain, "user", "invalid-pass", IMAP, "192.168.0.1"))

	test(t, b,
		req(Plain, "user", "invalid-pass", IMAP, "192.168.0.1"),
		res("Invalid username or password", 2, "", 0))
}

// TODO Max delay caps delay time
// TODO Client-IP-based delay
// TODO client-Ip + username delay uses min(client, username)
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
