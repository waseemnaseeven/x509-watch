package certloader

import (
	"errors"
	"fmt"
	"time"
)

type CertInfo struct {
	FilePath   string
	CommonName string
	Issuer     string
	NotBefore  time.Time
	NotAfter   time.Time
}

// Return time expiration (negative if already expired)
func (c *CertInfo) ExpiresInSeconds(now time.Time) float64 {
	return c.NotAfter.Sub(now).Seconds()
}

// Return elapsed time since beginning validity
func (c *CertInfo) ValidSinceSeconds(now time.Time) float64 {
	return now.Sub(c.NotBefore).Seconds()
}

// Indicate if certificate expire now
func (c *CertInfo) IsExpired(now time.Time) bool {
	return now.After(c.NotAfter)
}

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
	if err == nil {
		err = errors.New(string(t))
	}
	return &CertError{
		Path: path,
		Type: t,
		Err:  err,
	}
}
