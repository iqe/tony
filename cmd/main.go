package main

import (
	"fmt"
	"log"
	"net/http"

	t "iqe.io/tony"
)

func main() {

	// Example config for webflow mail proxy

	communigate := t.Mailserver(
		t.Endpoints{
			t.IMAP: t.NewEndpoint("localhost", 1143, t.SSLOff),
			t.POP3: t.NewEndpoint("localhost", 1110, t.SSLOff),
			t.SMTP: t.NewEndpoint("localhost", 1025, t.SSLOff),
		},
		t.Frankie("http://localhost:19000",
			t.IMAPLogin(t.NewEndpoint("localhost", 1143, t.SSLOff)),
		),
	)

	mailserver4 := t.Mailserver(
		t.Endpoints{
			t.IMAP: t.NewEndpoint("localhost", 4143, t.SSLOff),
			t.POP3: t.NewEndpoint("localhost", 4110, t.SSLOff),
			t.SMTP: t.NewEndpoint("localhost", 4025, t.SSLOff),
		},
		t.IMAPLogin(t.NewEndpoint("localhost", 4143, t.SSLOff)),
	)

	authHandler := t.RequestThrottling(2, 16,
		t.AnyOf(
			t.AllowedMethods([]t.Method{t.Plain}, mailserver4),
			t.AllowedMethods([]t.Method{t.Plain, t.CramMD5}, communigate),
		),
	)

	// Overwrites the above config!

	authHandler = t.RequestThrottling(2, 16,
		t.AllowedMethods([]t.Method{t.Plain},
			t.AnyOf(
				t.Mailserver(
					t.Endpoints{
						t.IMAP: t.NewEndpoint("mail.iqe.io", 143, t.STARTTLS),
						t.SMTP: t.NewEndpoint("mail.iqe.io", 587, t.STARTTLS),
					},
					t.IMAPLogin(t.NewEndpoint("mail.iqe.io", 993, t.SSLOn))),
				t.Mailserver(
					t.Endpoints{
						t.IMAP: t.NewEndpoint("mailserver.webflow.de", 143, t.SSLOff),
						t.POP3: t.NewEndpoint("mailserver.webflow.de", 110, t.SSLOff),
						t.SMTP: t.NewEndpoint("mailserver.webflow.de", 25, t.SSLOff),
					},
					t.Frankie("http://localhost:9000",
						t.IMAPLogin(t.NewEndpoint("mailserver.webflow.de", 143, t.SSLOff)),
					),
				),
			),
		),
	)

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
