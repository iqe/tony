package tony

type MethodGate struct {
	AuthHandler    AuthHandler
	allowedMethods []Method
}

func NewMethodGate(allowedMethods ...Method) *MethodGate {
	return &MethodGate{allowedMethods: allowedMethods}
}

func (m *MethodGate) Authenticate(request Request) Response {
	for _, method := range m.allowedMethods {
		if request.AuthMethod == method {
			return m.AuthHandler.Authenticate(request)
		}
	}

	return Response{AuthStatus: "Authentication method not supported"}
}
