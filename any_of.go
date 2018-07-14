package tony

type anyOfHandler struct {
	next []AuthHandler
}

func AnyOf(next ...AuthHandler) AuthHandler {
	return &anyOfHandler{next: next}
}

func (h *anyOfHandler) Authenticate(request Request) Response {
	for _, AuthHandler := range h.next {
		response := AuthHandler.Authenticate(request)
		if response.AuthStatus == authStatusOK {
			return response
		}
	}

	return Response{AuthStatus: "Invalid username or password"}
}
