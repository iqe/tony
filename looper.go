package tony

type looper struct {
	next []AuthHandler
}

func AnyOf(next ...AuthHandler) AuthHandler {
	return &looper{next: next}
}

func (l *looper) With(next AuthHandler) AuthHandler {
	panic("Use AnyOf() to chain AuthHandlers")
}

func (l *looper) Authenticate(request Request) Response {
	for _, AuthHandler := range l.next {
		response := AuthHandler.Authenticate(request)
		if response.AuthStatus == authStatusOK {
			return response
		}
	}

	return Response{AuthStatus: "Invalid username or password"}
}
