package tony

type allowedMethodsHandler struct {
	next    AuthHandler
	methods []Method
}

func AllowedMethods(methods []Method, next AuthHandler) AuthHandler {
	return &allowedMethodsHandler{methods: methods, next: next}
}

func (h *allowedMethodsHandler) Authenticate(request Request) Response {
	for _, method := range h.methods {
		if request.AuthMethod == method {
			return h.next.Authenticate(request)
		}
	}

	return Response{AuthStatus: "Authentication method not supported"}
}
