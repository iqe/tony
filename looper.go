package tony

type looper struct {
	next []AuthHandler
}

func AnyOf() AuthHandler {
	return &looper{}
}

func (l *looper) With(next AuthHandler) AuthHandler {
	l.next = append(l.next, next)
	return l
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
