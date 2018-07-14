package main

import (
	"fmt"
	"log"
	"net/http"

	t "iqe.io/tony"
)

func main() {
	authHandler := t.RequestThrottling(2, 16).With(
		t.AllowedMethods(t.Plain).With(
			t.AnyOf(
				t.EndpointSelection(map[t.Protocol]t.Endpoint{
					t.IMAP: t.NewEndpoint("mail.iqe.io", 143, t.STARTTLS),
					t.SMTP: t.NewEndpoint("mail.iqe.io", 587, t.STARTTLS)}).With(
					t.IMAPLogin(t.NewEndpoint("mail.iqe.io", 993, t.SSLOn))))))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		authRequest := parseAuthRequest(r)
		authResponse := authHandler.Authenticate(authRequest)
		writeAuthResponse(authResponse, w)

		w.Header()["Date"] = nil // Remove default Date header
	})

	log.Print("Starting server at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func parseAuthRequest(r *http.Request) t.Request {
	return t.Request{
		AuthMethod:   parseAuthMethod(r.Header.Get("Auth-Method")),
		AuthUser:     r.Header.Get("Auth-User"),
		AuthPass:     r.Header.Get("Auth-Pass"),
		AuthProtocol: parseAuthProtocol(r.Header.Get("Auth-Proto")),
		ClientIP:     r.Header.Get("Client-IP"),
	}
}

func parseAuthMethod(m string) t.Method {
	switch m {
	case "PLAIN", "LOGIN":
		return t.Plain
	case "CRAM-MD5":
		return t.CramMD5
	case "DIGEST-MD5":
		return t.DigestMD5
	default:
		return t.OtherMethod
	}
}

func parseAuthProtocol(p string) t.Protocol {
	switch p {
	case "smtp":
		return t.SMTP
	case "imap":
		return t.IMAP
	case "pop3":
		return t.POP3
	default:
		return t.OtherProtocol
	}
}

func writeAuthResponse(authResponse t.Response, w http.ResponseWriter) {
	w.Header().Add("Auth-Status", authResponse.AuthStatus)
	w.Header().Add("Auth-Server", authResponse.AuthServer)
	w.Header().Add("Auth-Port", fmt.Sprintf("%d", authResponse.AuthPort))
	w.Header().Add("Auth-Wait", fmt.Sprintf("%d", authResponse.AuthWait))
}
