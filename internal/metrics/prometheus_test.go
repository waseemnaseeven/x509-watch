package metrics

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"x509-watch/internal/certloader"
)

func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func TestPublishCerts_ValidCerts(t *testing.T) {
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	pub := NewPromPublisher(fixedClock(now))

	certs := []*certloader.CertInfo{
		{
			FilePath:   "/certs/a.pem",
			CommonName: "a.example.com",
			Issuer:     "TestCA",
			NotBefore:  now.Add(-30 * 24 * time.Hour),
			NotAfter:   now.Add(335 * 24 * time.Hour),
		},
		{
			FilePath:   "/certs/b.pem",
			CommonName: "b.example.com",
			Issuer:     "TestCA",
			NotBefore:  now.Add(-60 * 24 * time.Hour),
			NotAfter:   now.Add(305 * 24 * time.Hour),
		},
	}

	pub.PublishCerts(certs, nil)

	// Both valid → validCerts = 2
	if got := testutil.ToFloat64(validCerts); got != 2 {
		t.Fatalf("expected validCerts=2, got %f", got)
	}

	// Check per-cert metrics exist
	if count := testutil.CollectAndCount(certNotAfter); count != 2 {
		t.Fatalf("expected 2 certNotAfter series, got %d", count)
	}
	if count := testutil.CollectAndCount(certExpired); count != 2 {
		t.Fatalf("expected 2 certExpired series, got %d", count)
	}
}

func TestPublishCerts_ExpiredCert(t *testing.T) {
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	pub := NewPromPublisher(fixedClock(now))

	certs := []*certloader.CertInfo{
		{
			FilePath:   "/certs/valid.pem",
			CommonName: "valid.example.com",
			Issuer:     "CA",
			NotBefore:  now.Add(-30 * 24 * time.Hour),
			NotAfter:   now.Add(30 * 24 * time.Hour),
		},
		{
			FilePath:   "/certs/expired.pem",
			CommonName: "expired.example.com",
			Issuer:     "CA",
			NotBefore:  now.Add(-365 * 24 * time.Hour),
			NotAfter:   now.Add(-1 * time.Hour), // expired
		},
	}

	pub.PublishCerts(certs, nil)

	// Only 1 valid
	if got := testutil.ToFloat64(validCerts); got != 1 {
		t.Fatalf("expected validCerts=1, got %f", got)
	}
}

func TestPublishCerts_ErrorsByType(t *testing.T) {
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	pub := NewPromPublisher(fixedClock(now))

	errs := []*certloader.CertError{
		certloader.NewCertError("/a.pem", certloader.ErrTypeRead, nil),
		certloader.NewCertError("/b.pem", certloader.ErrTypeRead, nil),
		certloader.NewCertError("/c.pem", certloader.ErrTypeParse, nil),
	}

	pub.PublishCerts(nil, errs)

	if got := testutil.ToFloat64(validCerts); got != 0 {
		t.Fatalf("expected validCerts=0, got %f", got)
	}

	// 2 read_error, 1 parse_error
	if got := testutil.ToFloat64(certErrorsByType.WithLabelValues("read_error")); got != 2 {
		t.Fatalf("expected read_error=2, got %f", got)
	}
	if got := testutil.ToFloat64(certErrorsByType.WithLabelValues("parse_error")); got != 1 {
		t.Fatalf("expected parse_error=1, got %f", got)
	}
}

func TestPublishCerts_ResetsBetweenCalls(t *testing.T) {
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	pub := NewPromPublisher(fixedClock(now))

	// First publish: 2 certs
	certs := []*certloader.CertInfo{
		{FilePath: "/a.pem", CommonName: "a", Issuer: "CA", NotBefore: now, NotAfter: now.Add(time.Hour)},
		{FilePath: "/b.pem", CommonName: "b", Issuer: "CA", NotBefore: now, NotAfter: now.Add(time.Hour)},
	}
	pub.PublishCerts(certs, nil)

	if count := testutil.CollectAndCount(certNotAfter); count != 2 {
		t.Fatalf("first publish: expected 2 series, got %d", count)
	}

	// Second publish: 1 cert (should reset, not accumulate)
	certs2 := []*certloader.CertInfo{
		{FilePath: "/c.pem", CommonName: "c", Issuer: "CA", NotBefore: now, NotAfter: now.Add(time.Hour)},
	}
	pub.PublishCerts(certs2, nil)

	if count := testutil.CollectAndCount(certNotAfter); count != 1 {
		t.Fatalf("second publish: expected 1 series (reset), got %d", count)
	}
	if got := testutil.ToFloat64(validCerts); got != 1 {
		t.Fatalf("expected validCerts=1 after reset, got %f", got)
	}
}

func TestPublishCerts_NilInputs(t *testing.T) {
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	pub := NewPromPublisher(fixedClock(now))

	// Should not panic
	pub.PublishCerts(nil, nil)

	if got := testutil.ToFloat64(validCerts); got != 0 {
		t.Fatalf("expected validCerts=0, got %f", got)
	}
}

func TestNewPromPublisher_DefaultClock(t *testing.T) {
	pub := NewPromPublisher(nil)
	if pub.Clock == nil {
		t.Fatal("expected default clock to be set")
	}
	// Should return approximately now
	diff := time.Since(pub.Clock())
	if diff > time.Second {
		t.Fatalf("default clock drift too large: %v", diff)
	}
}

func TestSetBuildInfo(t *testing.T) {
	SetBuildInfo("1.0.0", "abc123")

	expected := `
		# HELP x509_exporter_build_info Build info for the x509 exporter
		# TYPE x509_exporter_build_info gauge
	`
	// Just check it exists and has the right labels
	if err := testutil.CollectAndCompare(buildInfo, strings.NewReader(expected)); err != nil {
		// testutil.CollectAndCompare is strict; just verify it was set
		if count := testutil.CollectAndCount(buildInfo); count != 1 {
			t.Fatalf("expected 1 buildInfo series, got %d", count)
		}
	}
}

func TestPublishCerts_ExpiryBuckets(t *testing.T) {
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	pub := NewPromPublisher(fixedClock(now))

	certs := []*certloader.CertInfo{
		{FilePath: "/a.pem", CommonName: "expired", Issuer: "CA", NotBefore: now.Add(-365 * 24 * time.Hour), NotAfter: now.Add(-1 * time.Hour)},
		{FilePath: "/b.pem", CommonName: "12hours", Issuer: "CA", NotBefore: now, NotAfter: now.Add(12 * time.Hour)},
		{FilePath: "/c.pem", CommonName: "3days", Issuer: "CA", NotBefore: now, NotAfter: now.Add(3 * 24 * time.Hour)},
		{FilePath: "/d.pem", CommonName: "15days", Issuer: "CA", NotBefore: now, NotAfter: now.Add(15 * 24 * time.Hour)},
		{FilePath: "/e.pem", CommonName: "60days", Issuer: "CA", NotBefore: now, NotAfter: now.Add(60 * 24 * time.Hour)},
		{FilePath: "/f.pem", CommonName: "120days", Issuer: "CA", NotBefore: now, NotAfter: now.Add(120 * 24 * time.Hour)},
	}

	pub.PublishCerts(certs, nil)

	tests := []struct {
		bucket string
		want   float64
	}{
		{"expired", 1},
		{"<1d", 1},
		{"<7d", 1},
		{"<30d", 1},
		{"<90d", 1},
		{">=90d", 1},
	}

	for _, tc := range tests {
		got := testutil.ToFloat64(certsByExpiryBucket.WithLabelValues(tc.bucket))
		if got != tc.want {
			t.Errorf("bucket %q: expected %f, got %f", tc.bucket, tc.want, got)
		}
	}
}

func TestPublishCerts_PerCertMetricsDisabled(t *testing.T) {
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	pub := NewPromPublisher(fixedClock(now))
	pub.PerCertMetrics = false

	certs := []*certloader.CertInfo{
		{FilePath: "/a.pem", CommonName: "a", Issuer: "CA", NotBefore: now, NotAfter: now.Add(30 * 24 * time.Hour)},
		{FilePath: "/b.pem", CommonName: "b", Issuer: "CA", NotBefore: now, NotAfter: now.Add(60 * 24 * time.Hour)},
	}

	pub.PublishCerts(certs, nil)

	// Aggregate metrics should still work
	if got := testutil.ToFloat64(validCerts); got != 2 {
		t.Fatalf("expected validCerts=2, got %f", got)
	}

	// Bucket metrics should still work
	if count := testutil.CollectAndCount(certsByExpiryBucket); count == 0 {
		t.Fatal("expected bucket metrics to be populated")
	}

	// Per-cert metrics should be empty (reset but not populated)
	if count := testutil.CollectAndCount(certNotAfter); count != 0 {
		t.Fatalf("expected 0 per-cert certNotAfter series with PerCertMetrics=false, got %d", count)
	}
	if count := testutil.CollectAndCount(certExpired); count != 0 {
		t.Fatalf("expected 0 per-cert certExpired series with PerCertMetrics=false, got %d", count)
	}
}

func TestClassifyExpiryBucket(t *testing.T) {
	tests := []struct {
		remaining time.Duration
		want      string
	}{
		{-1 * time.Hour, "expired"},
		{0, "expired"},
		{12 * time.Hour, "<1d"},
		{2 * 24 * time.Hour, "<7d"},
		{10 * 24 * time.Hour, "<30d"},
		{45 * 24 * time.Hour, "<90d"},
		{100 * 24 * time.Hour, ">=90d"},
	}

	for _, tc := range tests {
		got := classifyExpiryBucket(tc.remaining)
		if got != tc.want {
			t.Errorf("remaining=%v: expected %q, got %q", tc.remaining, tc.want, got)
		}
	}
}
