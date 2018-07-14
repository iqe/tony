package tony

type MethodGate struct {
	next           AuthHandler
	allowedMethods []Method
}

func NewMethodGate(allowedMethods ...Method) *MethodGate {
	return &MethodGate{allowedMethods: allowedMethods}
}

func (m *MethodGate) With(next AuthHandler) AuthHandler {
	m.next = next
	return m
}

func (m *MethodGate) Authenticate(request Request) Response {
	for _, method := range m.allowedMethods {
		if request.AuthMethod == method {
			return m.next.Authenticate(request)
		}
	}

	return Response{AuthStatus: "Authentication method not supported"}
}
