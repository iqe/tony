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

	if h.SSL == SSLOn {
		c, err = client.DialTLS(fmt.Sprintf("%s:%d", h.Server, h.Port), &tls.Config{
			ServerName: h.Server,
		})
		if err != nil {
			return err
		}
	} else {
		c, err = client.Dial(fmt.Sprintf("%s:%d", h.Server, h.Port))
		if err != nil {
			return err
		}
		if h.SSL == STARTTLS {
			err = c.StartTLS(&tls.Config{
				ServerName: h.Server,
			})
			if err != nil {
				return err
			}
		}
	}

	return c.Login(username, password)
}
