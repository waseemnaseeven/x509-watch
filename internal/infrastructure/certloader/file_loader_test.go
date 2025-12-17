package certloader

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"x509-watch/internal/infrastructure/log"
)

func TestFileLoader_InvalidPath(t *testing.T) {
	logger := log.NewLogger("debug")
	fl := NewFileLoader("does-not-exist.pem", logger)

	certs, errs := fl.LoadCertificates(context.Background())
	if len(certs) != 0 {
		t.Fatalf("expected no certs, got %d", len(certs))
	}
	if len(errs) == 0 {
		t.Fatalf("expected at least one error")
	}
}

func TestFileLoader_ValidPEM_NoCert(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dummy.pem")

	if err := os.WriteFile(path, []byte("NOT A CERT"), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	logger := log.NewLogger("debug")
	fl := NewFileLoader(path, logger)

	certs, errs := fl.LoadCertificates(context.Background())
	if len(certs) != 0 {
		t.Fatalf("expected no certs, got %d", len(certs))
	}
	if len(errs) == 0 {
		t.Fatalf("expected an error for invalid PEM")
	}
}
