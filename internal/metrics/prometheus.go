package metrics

import (
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"x509-watch/internal/certloader"
)

var (
	validCerts = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "x509_valid_certs_total",
			Help: "Number of current valid (non-expired) certificates",
		},
	)
	certNotBefore = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "x509_cert_not_before",
			Help: "Certificate validity start time (unix seconds)",
		},
		[]string{"common_name", "issuer", "filepath"},
	)

	certNotAfter = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "x509_cert_not_after",
			Help: "Certificate expiry time (unix seconds)",
		},
		[]string{"common_name", "issuer", "filepath"},
	)

	certExpired = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "x509_cert_expired",
			Help: "1 if certificate is expired, 0 otherwise",
		},
		[]string{"common_name", "issuer", "filepath"},
	)

	certExpiresInSeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "x509_cert_expires_in_seconds",
			Help: "Seconds until certificate expiry (negative if expired)",
		},
		[]string{"common_name", "issuer", "filepath"},
	)

	certsByExpiryBucket = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "x509_certs_by_expiry_bucket",
			Help: "Number of certificates grouped by expiry time range",
		},
		[]string{"range"},
	)

	certErrorsByType = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "x509_cert_errors_total",
			Help: "Number of certificates load errors by type in the last scan",
		},
		[]string{"error_type"}, // read, parse, pem, unknown
	)

	buildInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "x509_exporter_build_info",
			Help: "Build info for the x509 exporter",
		},
		[]string{"version", "revision", "goversion"},
	)
)

// expiryBuckets defines the ranges for certificate expiry bucketing.
// Ordered from most urgent to least. A cert falls into the first matching bucket.
var expiryBuckets = []struct {
	Label     string
	Threshold time.Duration
}{
	{"expired", 0},
	{"<1d", 24 * time.Hour},
	{"<7d", 7 * 24 * time.Hour},
	{"<30d", 30 * 24 * time.Hour},
	{"<90d", 90 * 24 * time.Hour},
	{">=90d", 0}, // catch-all
}

func init() {
	prometheus.MustRegister(
		validCerts,
		certNotBefore,
		certNotAfter,
		certExpired,
		certExpiresInSeconds,
		certsByExpiryBucket,
		certErrorsByType,
		buildInfo,
	)
}

// PromPublisher publishes certificate metrics to Prometheus.
type PromPublisher struct {
	Clock          func() time.Time
	PerCertMetrics bool // when false, only aggregate/bucket metrics are published
}

func NewPromPublisher(clock func() time.Time) *PromPublisher {
	if clock == nil {
		clock = time.Now
	}
	return &PromPublisher{Clock: clock, PerCertMetrics: true}
}

func boolToFloat(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

func (p *PromPublisher) PublishCerts(certs []*certloader.CertInfo, errs []*certloader.CertError) {

	// Reset all metrics before republishing
	certNotBefore.Reset()
	certNotAfter.Reset()
	certExpired.Reset()
	certExpiresInSeconds.Reset()
	certsByExpiryBucket.Reset()
	certErrorsByType.Reset()

	now := p.Clock()

	validCount := 0
	bucketCounts := make(map[string]int)
	for _, b := range expiryBuckets {
		bucketCounts[b.Label] = 0
	}

	for _, c := range certs {
		expiresIn := c.ExpiresInSeconds(now)
		expired := c.IsExpired(now)

		if p.PerCertMetrics {
			labels := prometheus.Labels{
				"common_name": c.CommonName,
				"issuer":      c.Issuer,
				"filepath":    c.FilePath,
			}
			certNotBefore.With(labels).Set(float64(c.NotBefore.Unix()))
			certNotAfter.With(labels).Set(float64(c.NotAfter.Unix()))
			certExpired.With(labels).Set(boolToFloat(expired))
			certExpiresInSeconds.With(labels).Set(expiresIn)
		}

		if !expired {
			validCount++
		}

		// Classify into expiry bucket
		remaining := time.Duration(expiresIn) * time.Second
		bucketCounts[classifyExpiryBucket(remaining)]++
	}

	validCerts.Set(float64(validCount))

	for label, count := range bucketCounts {
		certsByExpiryBucket.WithLabelValues(label).Set(float64(count))
	}

	errorsByType := make(map[certloader.CertErrorType]int)
	for _, e := range errs {
		errorsByType[e.Type]++
	}

	for errType, count := range errorsByType {
		certErrorsByType.WithLabelValues(string(errType)).Set(float64(count))
	}
}

func classifyExpiryBucket(remaining time.Duration) string {
	if remaining <= 0 {
		return "expired"
	}
	for _, b := range expiryBuckets {
		if b.Label == "expired" || b.Label == ">=90d" {
			continue
		}
		if remaining < b.Threshold {
			return b.Label
		}
	}
	return ">=90d"
}

func SetBuildInfo(version, revision string) {
	buildInfo.With(prometheus.Labels{
		"version":   version,
		"revision":  revision,
		"goversion": runtime.Version(),
	}).Set(1.0)
}
