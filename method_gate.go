package tony

type methodGate struct {
	next           AuthHandler
	allowedMethods []Method
}

func AllowedMethods(allowedMethods []Method, next AuthHandler) AuthHandler {
	return &methodGate{allowedMethods: allowedMethods, next: next}
}

func (m *methodGate) Authenticate(request Request) Response {
	for _, method := range m.allowedMethods {
		if request.AuthMethod == method {
			return m.next.Authenticate(request)
		}
	}

	return Response{AuthStatus: "Authentication method not supported"}
}
