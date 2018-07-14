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

type endpointSelect struct {
	next      AuthHandler
	endpoints Endpoints
}

func NewEndpointSelect(endpoints Endpoints) AuthHandler {
	return &endpointSelect{endpoints: endpoints}
}

func (h *endpointSelect) With(next AuthHandler) AuthHandler {
	h.next = next
	return h
}

func (h *endpointSelect) Authenticate(r Request) Response {
	response := h.next.Authenticate(r)

	endpoint, ok := h.endpoints[r.AuthProtocol]
	if ok {
		response.AuthServer = endpoint.Server
		response.AuthPort = endpoint.Port
		return response
	}

	return Response{AuthStatus: fmt.Sprintf("Unsupported protocol: %v", r.AuthProtocol)}
}
