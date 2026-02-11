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

func init() {
	prometheus.MustRegister(
		validCerts,
		certNotBefore,
		certNotAfter,
		certExpired,
		certExpiresInSeconds,
		certErrorsByType,
		buildInfo,
	)
}

// PromPublisher publishes certificate metrics to Prometheus.
type PromPublisher struct {
	Clock func() time.Time
}

func NewPromPublisher(clock func() time.Time) *PromPublisher {
	if clock == nil {
		clock = time.Now
	}
	return &PromPublisher{Clock: clock}
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
	certErrorsByType.Reset()

	now := p.Clock()

	validCount := 0

	for _, c := range certs {
		labels := prometheus.Labels{
			"common_name": c.CommonName,
			"issuer":      c.Issuer,
			"filepath":    c.FilePath,
		}

		notBefore := float64(c.NotBefore.Unix())
		notAfter := float64(c.NotAfter.Unix())
		expiresIn := c.ExpiresInSeconds(now)
		expired := c.IsExpired(now)

		certNotBefore.With(labels).Set(notBefore)
		certNotAfter.With(labels).Set(notAfter)
		certExpired.With(labels).Set(boolToFloat(expired))
		certExpiresInSeconds.With(labels).Set(expiresIn)

		if !expired {
			validCount++
		}
	}

	validCerts.Set(float64(validCount))

	errorsByType := make(map[certloader.CertErrorType]int)
	for _, e := range errs {
		errorsByType[e.Type]++
	}

	for errType, count := range errorsByType {
		certErrorsByType.WithLabelValues(string(errType)).Set(float64(count))
	}
}

func SetBuildInfo(version, revision string) {
	buildInfo.With(prometheus.Labels{
		"version":   version,
		"revision":  revision,
		"goversion": runtime.Version(),
	}).Set(1.0)
}
