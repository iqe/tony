package tony

import (
	"fmt"
)

type SSL int

const (
	SSLOn SSL = iota
	SSLOff
	STARTTLS
)

type Endpoint struct {
	server string
	port   int
	ssl    SSL
}

func NewEndpoint(server string, port int, ssl SSL) Endpoint {
	return Endpoint{
		server: server,
		port:   port,
		ssl:    ssl,
	}
}

type Endpoints map[Protocol]Endpoint

type mailserverHandler struct {
	next      AuthHandler
	endpoints Endpoints
}

func Mailserver(endpoints Endpoints, next AuthHandler) AuthHandler {
	return &mailserverHandler{endpoints: endpoints, next: next}
}

func (h *mailserverHandler) Authenticate(r Request) Response {
	response := h.next.Authenticate(r)

	endpoint, ok := h.endpoints[r.AuthProtocol]
	if ok {
		response.AuthServer = endpoint.server
		response.AuthPort = endpoint.port
		return response
	}

	return Response{AuthStatus: fmt.Sprintf("Unsupported protocol: %v", r.AuthProtocol)}
}
