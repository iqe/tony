package tony

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type frankieHandler struct {
	next    AuthHandler
	baseURL string
}

func Frankie(baseURL string, next AuthHandler) AuthHandler {
	return &frankieHandler{
		baseURL: baseURL,
		next:    next,
	}
}

func (h *frankieHandler) Authenticate(r Request) Response {
	parts := strings.Split(r.AuthUser, "@")

	if len(parts) != 2 {
		return Response{
			AuthStatus: fmt.Sprintf("invalid username: %s", r.AuthUser),
		}
	}

	mailbox := parts[0]
	domain := parts[1]

	if err := h.checkMailbox(mailbox, domain); err != nil {
		return Response{
			AuthStatus: err.Error(),
		}
	}

	return h.next.Authenticate(r)
}

func (h *frankieHandler) checkMailbox(mailbox string, domain string) error {
	resp, err := http.Get(fmt.Sprintf("%s?mailbox=%s&domain=%s", h.baseURL, mailbox, domain))
	if err != nil {
		return err
	}

	if resp.StatusCode == http.StatusNotFound {
		return errors.New(fmt.Sprintf("unknown user: %s@%s", mailbox, domain))
	}

	if resp.StatusCode != http.StatusOK {
		return errors.New(fmt.Sprintf("frankie returned %s for user %s@%s", resp.Status, mailbox, domain))
	}

	return nil
}
