package tony

import (
	"crypto/tls"
	"fmt"

	"github.com/emersion/go-imap/client"
)

type imapLoginHandler struct {
	Endpoint
}

func IMAPLogin(endpoint Endpoint) AuthHandler {
	return &imapLoginHandler{
		Endpoint: endpoint,
	}
}

func (h *imapLoginHandler) Authenticate(r Request) Response {
	err := h.imapLogin(r.AuthUser, r.AuthPass)

	if err != nil {
		return Response{
			AuthStatus: err.Error(),
		}
	}

	return Response{
		AuthStatus: authStatusOK,
	}
}

func (h *imapLoginHandler) imapLogin(username string, password string) error {
	var err error
	var c *client.Client

	if h.ssl == SSLOn {
		c, err = client.DialTLS(fmt.Sprintf("%s:%d", h.server, h.port), &tls.Config{
			ServerName: h.server,
		})
		if err != nil {
			return err
		}
	} else {
		c, err = client.Dial(fmt.Sprintf("%s:%d", h.server, h.port))
		if err != nil {
			return err
		}
		if h.ssl == STARTTLS {
			err = c.StartTLS(&tls.Config{
				ServerName: h.server,
			})
			if err != nil {
				return err
			}
		}
	}

	return c.Login(username, password)
}
