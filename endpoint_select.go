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
	Server string
	Port   int
	SSL    SSL
}

func NewEndpoint(server string, port int, ssl SSL) Endpoint {
	return Endpoint{
		Server: server,
		Port:   port,
		SSL:    ssl,
	}
}

type Endpoints map[Protocol]Endpoint

type EndpointSelect struct {
	next      AuthHandler
	Endpoints Endpoints
}

func NewEndpointSelect(endpoints Endpoints) *EndpointSelect {
	return &EndpointSelect{Endpoints: endpoints}
}

func (h *EndpointSelect) With(next AuthHandler) AuthHandler {
	h.next = next
	return h
}

func (h *EndpointSelect) Authenticate(r Request) Response {
	response := h.next.Authenticate(r)

	endpoint, ok := h.Endpoints[r.AuthProtocol]
	if ok {
		response.AuthServer = endpoint.Server
		response.AuthPort = endpoint.Port
		return response
	}

	return Response{AuthStatus: fmt.Sprintf("Unsupported protocol: %v", r.AuthProtocol)}
}
