package tony

type Looper struct {
	next []AuthHandler
}

func NewLooper() *Looper {
	return &Looper{}
}

func (l *Looper) With(next AuthHandler) AuthHandler {
	l.next = append(l.next, next)
	return l
}

func (l *Looper) Authenticate(request Request) Response {
	for _, AuthHandler := range l.next {
		response := AuthHandler.Authenticate(request)
		if response.AuthStatus == AuthStatusOK {
			return response
		}
	}

	return Response{AuthStatus: "Invalid username or password"}
}
