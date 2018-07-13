package main

import (
	"fmt"
	"log"
	"net/http"

	"iqe.io/tony"
)

func main() {
	t := &tony.Tony{}
	throttler := tony.NewThrottler(2, 16)
	methodGate := tony.NewMethodGate(tony.Plain)
	looper := tony.NewLooper()

	t.AuthHandler = throttler
	throttler.AuthHandler = methodGate
	methodGate.AuthHandler = looper

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		authRequest := parseAuthRequest(r)
		authResponse := t.Authenticate(authRequest)
		writeAuthResponse(authResponse, w)

		w.Header()["Date"] = nil // Remove default Date header
	})

	log.Print("Starting server at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func parseAuthRequest(r *http.Request) tony.Request {
	return tony.Request{
		AuthMethod:   parseAuthMethod(r.Header.Get("Auth-Method")),
		AuthUser:     r.Header.Get("Auth-User"),
		AuthPass:     r.Header.Get("Auth-Pass"),
		AuthProtocol: parseAuthProtocol(r.Header.Get("Auth-Proto")),
		ClientIP:     r.Header.Get("Client-IP"),
	}
}

func parseAuthMethod(m string) tony.Method {
	switch m {
	case "PLAIN", "LOGIN":
		return tony.Plain
	case "CRAM-MD5":
		return tony.CramMD5
	case "DIGEST-MD5":
		return tony.DigestMD5
	default:
		return tony.OtherMethod
	}
}

func parseAuthProtocol(p string) tony.Protocol {
	switch p {
	case "smtp":
		return tony.SMTP
	case "imap":
		return tony.IMAP
	case "pop3":
		return tony.POP3
	default:
		return tony.OtherProtocol
	}
}

func writeAuthResponse(authResponse tony.Response, w http.ResponseWriter) {
	w.Header().Add("Auth-Status", authResponse.AuthStatus)
	w.Header().Add("Auth-Server", authResponse.AuthServer)
	w.Header().Add("Auth-Port", fmt.Sprintf("%d", authResponse.AuthPort))
	w.Header().Add("Auth-Wait", fmt.Sprintf("%d", authResponse.AuthWait))
}
