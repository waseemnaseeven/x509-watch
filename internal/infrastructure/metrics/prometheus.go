// TODO: Metrics openMetrics Standard, prometheus gaugeVec with init

package metrics

import (
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"x509-watch/internal/entity"
)

var (
	validCerts = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "x509_valid_certs",
			Help: "Number of current valid certs observed by x509-watch",
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

	certErrorGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "x509_cert_error",
			Help: "1 if an error occurred for this cert file, labelled by error_type",
		},
		[]string{"filepath", "error_type"},
	)

	readErrorsCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "x509_read_errors",
			Help: "Total number of certificate read/parse errors",
		},
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
		certErrorGauge,
		readErrorsCounter,
		buildInfo,
	)
}

// PromPublisher implement MetricsPublisher.
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

func (p *PromPublisher) PublishCerts(certs []*entity.CertInfo, errs []*entity.CertError) {

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

	for _, e := range errs {
		readErrorsCounter.Inc()
		certErrorGauge.With(prometheus.Labels{
			"filepath":   e.Path,
			"error_type": string(e.Type),
		}).Set(1.0)
	}
}

func SetBuildInfo(version, revision string) {
	buildInfo.With(prometheus.Labels{
		"version":   version,
		"revision":  revision,
		"goversion": runtime.Version(),
	}).Set(1.0)
}
