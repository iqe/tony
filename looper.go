package tony

type Looper struct {
	AuthHandlers []AuthHandler
}

func NewLooper() *Looper {
	return &Looper{}
}

func (l *Looper) Authenticate(request Request) Response {
	for _, AuthHandler := range l.AuthHandlers {
		response := AuthHandler.Authenticate(request)
		if response.AuthStatus == AuthStatusOK {
			return response
		}
	}

	return Response{AuthStatus: "Invalid username or password"}
}
