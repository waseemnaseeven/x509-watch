package entity

import (
	"errors"
	"fmt"
)

type CertErrorType string

const (
	ErrTypeRead    CertErrorType = "read_error"
	ErrTypeParse   CertErrorType = "parse_error"
	ErrTypePEM     CertErrorType = "pem_error"
	ErrTypeUnknown CertErrorType = "unknown_error"
)

// Encapsulation of an error of a certificate
type CertError struct {
	Path string
	Type CertErrorType
	Err  error
}

// return error function
func (e *CertError) Error() string {
	return fmt.Sprintf("cert error [%s] on %s: %v", e.Type, e.Path, e.Err)
}

// unwrap is to use error.is() / error.as()
func (e *CertError) Unwrap() error {
	return e.Err
}

func NewCertError(path string, t CertErrorType, err error) *CertError {
	if err != nil {
		err = errors.New(string(t))
	}
	return &CertError{}
}
