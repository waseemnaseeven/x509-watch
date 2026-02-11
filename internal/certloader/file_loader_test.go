package certloader

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// generateTestCertDER returns raw DER bytes for a self-signed certificate.
func generateTestCertDER(t *testing.T, cn string, notBefore, notAfter time.Time) []byte {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return der
}

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

func TestFileLoader_InvalidPath(t *testing.T) {
	fl := NewFileLoader("does-not-exist.pem", slog.Default())

	certs, errs := fl.LoadCertificates(context.Background())
	if len(certs) != 0 {
		t.Fatalf("expected no certs, got %d", len(certs))
	}
	if len(errs) == 0 {
		t.Fatalf("expected at least one error")
	}
	if errs[0].Type != ErrTypeRead {
		t.Fatalf("expected ErrTypeRead, got %s", errs[0].Type)
	}
}

func TestFileLoader_ValidPEM_NoCert(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "dummy.pem", []byte("NOT A CERT"))

	fl := NewFileLoader(path, slog.Default())

	certs, errs := fl.LoadCertificates(context.Background())
	if len(certs) != 0 {
		t.Fatalf("expected no certs, got %d", len(certs))
	}
	if len(errs) == 0 {
		t.Fatalf("expected an error for invalid PEM")
	}
}

func TestFileLoader_ValidPEM_SingleCert(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	der := generateTestCertDER(t, "single.example.com", now, now.Add(365*24*time.Hour))
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	path := writeFile(t, dir, "single.pem", pemData)

	fl := NewFileLoader(path, slog.Default())
	certs, errs := fl.LoadCertificates(context.Background())

	if len(errs) != 0 {
		t.Fatalf("expected 0 errors, got %d: %v", len(errs), errs)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	if certs[0].CommonName != "single.example.com" {
		t.Fatalf("expected CN=single.example.com, got %s", certs[0].CommonName)
	}
	if certs[0].FilePath != path {
		t.Fatalf("expected filepath=%s, got %s", path, certs[0].FilePath)
	}
}

func TestFileLoader_ValidPEM_MultipleCerts(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()

	var combined []byte
	cns := []string{"cert1.example.com", "cert2.example.com", "cert3.example.com"}
	for _, cn := range cns {
		der := generateTestCertDER(t, cn, now, now.Add(365*24*time.Hour))
		combined = append(combined, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	path := writeFile(t, dir, "multi.pem", combined)

	fl := NewFileLoader(path, slog.Default())
	certs, errs := fl.LoadCertificates(context.Background())

	if len(errs) != 0 {
		t.Fatalf("expected 0 errors, got %d: %v", len(errs), errs)
	}
	if len(certs) != 3 {
		t.Fatalf("expected 3 certs, got %d", len(certs))
	}
	for i, cn := range cns {
		if certs[i].CommonName != cn {
			t.Errorf("cert[%d]: expected CN=%s, got %s", i, cn, certs[i].CommonName)
		}
	}
}

func TestFileLoader_MixedValidAndInvalidPEMBlocks(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()

	// Valid cert
	der := generateTestCertDER(t, "valid.example.com", now, now.Add(365*24*time.Hour))
	validPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	// Malformed cert block
	malformedPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("GARBAGE")})

	combined := append(validPEM, malformedPEM...)
	path := writeFile(t, dir, "mixed.pem", combined)

	fl := NewFileLoader(path, slog.Default())
	certs, errs := fl.LoadCertificates(context.Background())

	if len(certs) != 1 {
		t.Fatalf("expected 1 valid cert, got %d", len(certs))
	}
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d", len(errs))
	}
	if errs[0].Type != ErrTypeParse {
		t.Fatalf("expected ErrTypeParse, got %s", errs[0].Type)
	}
}

func TestFileLoader_PEMWithNonCertBlock(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()

	// RSA private key block (should be skipped)
	keyBlock := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("fakekey")})
	// Valid cert
	der := generateTestCertDER(t, "withkey.example.com", now, now.Add(365*24*time.Hour))
	certBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	combined := append(keyBlock, certBlock...)
	path := writeFile(t, dir, "bundle.pem", combined)

	fl := NewFileLoader(path, slog.Default())
	certs, errs := fl.LoadCertificates(context.Background())

	if len(errs) != 0 {
		t.Fatalf("expected 0 errors, got %d: %v", len(errs), errs)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert (skipping key block), got %d", len(certs))
	}
}

func TestFileLoader_DERFormat(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()

	der := generateTestCertDER(t, "der.example.com", now, now.Add(365*24*time.Hour))
	path := writeFile(t, dir, "cert.der", der)

	fl := NewFileLoader(path, slog.Default())
	certs, errs := fl.LoadCertificates(context.Background())

	if len(errs) != 0 {
		t.Fatalf("expected 0 errors, got %d: %v", len(errs), errs)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	if certs[0].CommonName != "der.example.com" {
		t.Fatalf("expected CN=der.example.com, got %s", certs[0].CommonName)
	}
}

func TestFileLoader_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "empty.pem", []byte{})

	fl := NewFileLoader(path, slog.Default())
	certs, errs := fl.LoadCertificates(context.Background())

	if len(certs) != 0 {
		t.Fatalf("expected 0 certs, got %d", len(certs))
	}
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d", len(errs))
	}
	if errs[0].Type != ErrTypePEM {
		t.Fatalf("expected ErrTypePEM, got %s", errs[0].Type)
	}
}

func TestFileLoader_ContextCancelled(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	der := generateTestCertDER(t, "test.example.com", now, now.Add(365*24*time.Hour))
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	path := writeFile(t, dir, "cert.pem", pemData)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	fl := NewFileLoader(path, slog.Default())
	certs, errs := fl.LoadCertificates(ctx)

	if len(certs) != 0 {
		t.Fatalf("expected 0 certs on cancelled context, got %d", len(certs))
	}
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d", len(errs))
	}
	if errs[0].Type != ErrTypeUnknown {
		t.Fatalf("expected ErrTypeUnknown, got %s", errs[0].Type)
	}
}
