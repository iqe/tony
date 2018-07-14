package tony

import (
	"crypto/tls"
	"fmt"

	"github.com/emersion/go-imap/client"
)

type IMAPLogin struct {
	Endpoint
}

func NewIMAPLogin(endpoint Endpoint) *IMAPLogin {
	return &IMAPLogin{
		Endpoint: endpoint,
	}
}

func (h *IMAPLogin) With(next AuthHandler) AuthHandler {
	panic("imap login cannot be chained further")
}

func (h *IMAPLogin) Authenticate(r Request) Response {
	err := h.imapLogin(r.AuthUser, r.AuthPass)

	if err != nil {
		return Response{
			AuthStatus: err.Error(),
		}
	}

	return Response{
		AuthStatus: AuthStatusOK,
	}
}

func (h *IMAPLogin) imapLogin(username string, password string) error {
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
