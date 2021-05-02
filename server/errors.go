package server

type UserDoesNotExist struct {
	Err error
}

type AuthenticationFailed struct {
	Err error
}

type NoSecrets struct {
	Err error
}

type NonceGenerationError struct {
	Err error
}

func (e *UserDoesNotExist) Error() string {
	return e.Err.Error()
}

func (e *NoSecrets) Error() string {
	return e.Err.Error()
}

func (e *AuthenticationFailed) Error() string {
	return e.Err.Error()
}

func (e *NonceGenerationError) Error() string {
	return e.Err.Error()
}

func NewUserDoesNotExist(err error) error {
	return &UserDoesNotExist{err}
}

func NewNoSecrets(err error) error {
	return &NoSecrets{err}
}

func NewAuthenticationFailed(err error) error {
	return &AuthenticationFailed{err}
}

func NewNonceGenerationError(err error) error {
	return &NonceGenerationError{err}
}
