package tony

type methodGate struct {
	next           AuthHandler
	allowedMethods []Method
}

func NewMethodGate(allowedMethods ...Method) AuthHandler {
	return &methodGate{allowedMethods: allowedMethods}
}

func (m *methodGate) With(next AuthHandler) AuthHandler {
	m.next = next
	return m
}

func (m *methodGate) Authenticate(request Request) Response {
	for _, method := range m.allowedMethods {
		if request.AuthMethod == method {
			return m.next.Authenticate(request)
		}
	}

	return Response{AuthStatus: "Authentication method not supported"}
}
