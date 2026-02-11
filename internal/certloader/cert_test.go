package certloader

import (
	"errors"
	"testing"
	"time"
)

func TestCertificateInfo_IsExpired(t *testing.T) {
	now := time.Now()

	c := &CertInfo{
		NotAfter: now.Add(-1 * time.Hour),
	}
	if !c.IsExpired(now) {
		t.Fatalf("expected certificate to be expired")
	}

	c2 := &CertInfo{
		NotAfter: now.Add(1 * time.Hour),
	}
	if c2.IsExpired(now) {
		t.Fatalf("expected certificate to NOT be expired")
	}
}

func TestCertificateInfo_ExpiresInSeconds(t *testing.T) {
	now := time.Now()

	// Certificate expiring in 1 hour
	c := &CertInfo{NotAfter: now.Add(1 * time.Hour)}
	got := c.ExpiresInSeconds(now)
	if got < 3599 || got > 3601 {
		t.Fatalf("expected ~3600 seconds, got %f", got)
	}

	// Already expired certificate
	c2 := &CertInfo{NotAfter: now.Add(-30 * time.Minute)}
	got2 := c2.ExpiresInSeconds(now)
	if got2 > -1799 || got2 < -1801 {
		t.Fatalf("expected ~-1800 seconds, got %f", got2)
	}
}

func TestCertificateInfo_ValidSinceSeconds(t *testing.T) {
	now := time.Now()

	// Certificate valid since 2 hours ago
	c := &CertInfo{NotBefore: now.Add(-2 * time.Hour)}
	got := c.ValidSinceSeconds(now)
	if got < 7199 || got > 7201 {
		t.Fatalf("expected ~7200 seconds, got %f", got)
	}

	// Certificate not yet valid (future NotBefore)
	c2 := &CertInfo{NotBefore: now.Add(1 * time.Hour)}
	got2 := c2.ValidSinceSeconds(now)
	if got2 > -3599 || got2 < -3601 {
		t.Fatalf("expected ~-3600 seconds, got %f", got2)
	}
}

func TestCertError_Error(t *testing.T) {
	err := NewCertError("/path/cert.pem", ErrTypeParse, errors.New("bad ASN.1"))
	msg := err.Error()
	expected := "cert error [parse_error] on /path/cert.pem: bad ASN.1"
	if msg != expected {
		t.Fatalf("expected %q, got %q", expected, msg)
	}
}

func TestCertError_Unwrap(t *testing.T) {
	inner := errors.New("permission denied")
	cerr := NewCertError("/path/cert.pem", ErrTypeRead, inner)
	if !errors.Is(cerr, inner) {
		t.Fatalf("expected Unwrap to return the inner error")
	}
}

func TestNewCertError_NilErr(t *testing.T) {
	cerr := NewCertError("/path/cert.pem", ErrTypePEM, nil)
	if cerr.Err == nil {
		t.Fatalf("expected non-nil Err when passing nil")
	}
	if cerr.Err.Error() != string(ErrTypePEM) {
		t.Fatalf("expected default error message %q, got %q", ErrTypePEM, cerr.Err.Error())
	}
}
