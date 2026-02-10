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

// Helper function to generate a test certificate
func generateTestCert(t *testing.T, cn string, notBefore, notAfter time.Time) []byte {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return certPEM
}

func TestDirLoader_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	logger := slog.Default()
	loader := NewDirLoader(dir, logger)

	certs, errs := loader.LoadCertificates(context.Background())

	if len(certs) != 0 {
		t.Errorf("expected 0 certs, got %d", len(certs))
	}
	if len(errs) != 0 {
		t.Errorf("expected 0 errors, got %d", len(errs))
	}
}

func TestDirLoader_SingleCertificate(t *testing.T) {
	dir := t.TempDir()
	logger := slog.Default()

	// Generate and write a valid certificate
	now := time.Now()
	certPEM := generateTestCert(t, "test.example.com", now, now.Add(365*24*time.Hour))
	certPath := filepath.Join(dir, "test.pem")
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}

	loader := NewDirLoader(dir, logger)
	certs, errs := loader.LoadCertificates(context.Background())

	if len(errs) != 0 {
		t.Errorf("expected 0 errors, got %d: %v", len(errs), errs)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	if certs[0].CommonName != "test.example.com" {
		t.Errorf("expected CN=test.example.com, got %s", certs[0].CommonName)
	}
	if certs[0].FilePath != certPath {
		t.Errorf("expected filepath=%s, got %s", certPath, certs[0].FilePath)
	}
}

func TestDirLoader_MultipleCertificates(t *testing.T) {
	dir := t.TempDir()
	logger := slog.Default()

	now := time.Now()
	cns := []string{"cert1.example.com", "cert2.example.com", "cert3.example.com"}

	for i, cn := range cns {
		certPEM := generateTestCert(t, cn, now, now.Add(365*24*time.Hour))
		certPath := filepath.Join(dir, "cert"+string(rune('1'+i))+".pem")
		if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
			t.Fatalf("failed to write cert file: %v", err)
		}
	}

	loader := NewDirLoader(dir, logger)
	certs, errs := loader.LoadCertificates(context.Background())

	if len(errs) != 0 {
		t.Errorf("expected 0 errors, got %d: %v", len(errs), errs)
	}
	if len(certs) != len(cns) {
		t.Fatalf("expected %d certs, got %d", len(cns), len(certs))
	}

	// Verify all CNs are present
	foundCNs := make(map[string]bool)
	for _, cert := range certs {
		foundCNs[cert.CommonName] = true
	}
	for _, cn := range cns {
		if !foundCNs[cn] {
			t.Errorf("missing certificate with CN=%s", cn)
		}
	}
}

func TestDirLoader_NestedDirectories(t *testing.T) {
	dir := t.TempDir()
	logger := slog.Default()

	now := time.Now()

	// Root level cert
	certPEM1 := generateTestCert(t, "root.example.com", now, now.Add(365*24*time.Hour))
	if err := os.WriteFile(filepath.Join(dir, "root.pem"), certPEM1, 0644); err != nil {
		t.Fatalf("failed to write root cert: %v", err)
	}

	// Nested directory with cert
	subDir := filepath.Join(dir, "subdir")
	if err := os.Mkdir(subDir, 0755); err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}
	certPEM2 := generateTestCert(t, "sub.example.com", now, now.Add(365*24*time.Hour))
	if err := os.WriteFile(filepath.Join(subDir, "sub.pem"), certPEM2, 0644); err != nil {
		t.Fatalf("failed to write sub cert: %v", err)
	}

	// Deeply nested
	deepDir := filepath.Join(subDir, "deep")
	if err := os.Mkdir(deepDir, 0755); err != nil {
		t.Fatalf("failed to create deep dir: %v", err)
	}
	certPEM3 := generateTestCert(t, "deep.example.com", now, now.Add(365*24*time.Hour))
	if err := os.WriteFile(filepath.Join(deepDir, "deep.pem"), certPEM3, 0644); err != nil {
		t.Fatalf("failed to write deep cert: %v", err)
	}

	loader := NewDirLoader(dir, logger)
	certs, errs := loader.LoadCertificates(context.Background())

	if len(errs) != 0 {
		t.Errorf("expected 0 errors, got %d: %v", len(errs), errs)
	}
	if len(certs) != 3 {
		t.Fatalf("expected 3 certs, got %d", len(certs))
	}
}

func TestDirLoader_MixedValidAndInvalid(t *testing.T) {
	dir := t.TempDir()
	logger := slog.Default()

	now := time.Now()

	// Valid certificate
	certPEM := generateTestCert(t, "valid.example.com", now, now.Add(365*24*time.Hour))
	if err := os.WriteFile(filepath.Join(dir, "valid.pem"), certPEM, 0644); err != nil {
		t.Fatalf("failed to write valid cert: %v", err)
	}

	// Invalid file (not a certificate)
	if err := os.WriteFile(filepath.Join(dir, "invalid.txt"), []byte("not a cert"), 0644); err != nil {
		t.Fatalf("failed to write invalid file: %v", err)
	}

	// Malformed PEM
	if err := os.WriteFile(filepath.Join(dir, "malformed.pem"), []byte("-----BEGIN CERTIFICATE-----\nGARBAGE\n-----END CERTIFICATE-----"), 0644); err != nil {
		t.Fatalf("failed to write malformed cert: %v", err)
	}

	loader := NewDirLoader(dir, logger)
	certs, errs := loader.LoadCertificates(context.Background())

	if len(certs) != 1 {
		t.Errorf("expected 1 valid cert, got %d", len(certs))
	}
	if len(errs) < 2 {
		t.Errorf("expected at least 2 errors, got %d", len(errs))
	}
	if certs[0].CommonName != "valid.example.com" {
		t.Errorf("expected valid cert CN=valid.example.com, got %s", certs[0].CommonName)
	}
}

func TestDirLoader_NonExistentDirectory(t *testing.T) {
	logger := slog.Default()
	loader := NewDirLoader("/path/that/does/not/exist", logger)

	certs, errs := loader.LoadCertificates(context.Background())

	if len(certs) != 0 {
		t.Errorf("expected 0 certs, got %d", len(certs))
	}
	if len(errs) == 0 {
		t.Errorf("expected at least 1 error for non-existent directory")
	}
	if errs[0].Type != ErrTypeRead {
		t.Errorf("expected ErrTypeRead, got %s", errs[0].Type)
	}
}

func TestDirLoader_ContextCancellation(t *testing.T) {
	dir := t.TempDir()
	logger := slog.Default()

	now := time.Now()
	certPEM := generateTestCert(t, "test.example.com", now, now.Add(365*24*time.Hour))
	if err := os.WriteFile(filepath.Join(dir, "test.pem"), certPEM, 0644); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	loader := NewDirLoader(dir, logger)
	certs, errs := loader.LoadCertificates(ctx)

	// Should handle cancellation gracefully — no full results expected
	if len(certs) > 0 {
		t.Logf("got %d certs despite cancellation (may be expected)", len(certs))
	}
	// The key assertion: no panic, no hang, returns cleanly
	t.Logf("cancellation handled: %d certs, %d errs", len(certs), len(errs))
}

func TestDirLoader_IgnoreNonCertFiles(t *testing.T) {
	dir := t.TempDir()
	logger := slog.Default()

	now := time.Now()

	// Valid cert
	certPEM := generateTestCert(t, "valid.example.com", now, now.Add(365*24*time.Hour))
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), certPEM, 0644); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}

	// Text file
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("README"), 0644); err != nil {
		t.Fatalf("failed to write text file: %v", err)
	}

	// Binary file
	if err := os.WriteFile(filepath.Join(dir, "data.bin"), []byte{0x00, 0xFF, 0xAA}, 0644); err != nil {
		t.Fatalf("failed to write binary file: %v", err)
	}

	loader := NewDirLoader(dir, logger)
	certs, errs := loader.LoadCertificates(context.Background())

	if len(certs) != 1 {
		t.Errorf("expected 1 valid cert, got %d", len(certs))
	}
	// Non-cert files should generate errors
	if len(errs) < 2 {
		t.Errorf("expected at least 2 errors for non-cert files, got %d", len(errs))
	}
}

func TestNewDirLoader(t *testing.T) {
	logger := slog.Default()
	loader := NewDirLoader("/test/path", logger)

	if loader == nil {
		t.Fatal("NewDirLoader returned nil")
	}
	if loader.Root != "/test/path" {
		t.Errorf("expected Root=/test/path, got %s", loader.Root)
	}
	if loader.Logger == nil {
		t.Error("expected Logger to be set")
	}
}
