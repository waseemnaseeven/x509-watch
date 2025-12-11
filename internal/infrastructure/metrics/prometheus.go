// TODO: Metrics openMetrics Standard, prometheus gaugeVec with init

package metrics

import (
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"x509-watch/internal/entity"
)

var (
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

	certValidSinceSeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "x509_cert_valid_since_seconds",
			Help: "Seconds since certificate became valid",
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
		certNotBefore,
		certNotAfter,
		certExpired,
		certExpiresInSeconds,
		certValidSinceSeconds,
		certErrorGauge,
		readErrorsCounter,
		buildInfo,
	)
}

// PromPublisher implémente MetricsPublisher.
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

	for _, c := range certs {
		labels := prometheus.Labels{
			"common_name": c.CommonName,
			"issuer":      c.Issuer,
			"filepath":    c.FilePath,
		}
		certNotBefore.With(labels).Set(float64(c.NotBefore.Unix()))
		certNotAfter.With(labels).Set(float64(c.NotAfter.Unix()))
		certExpired.With(labels).Set(boolToFloat(c.IsExpired(now)))
		certExpiresInSeconds.With(labels).Set(c.ExpiresInSeconds(now))
		certValidSinceSeconds.With(labels).Set(c.ValidSinceSeconds(now))
	}

	for _, e := range errs {
		readErrorsCounter.Inc()
		certErrorGauge.With(prometheus.Labels{
			"filepath":   e.Path,
			"error_type": string(e.Type),
		}).Set(1.0)
	}
}

// SetBuildInfo doit être appelée une fois au démarrage.
func SetBuildInfo(version, revision string) {
	buildInfo.With(prometheus.Labels{
		"version":   version,
		"revision":  revision,
		"goversion": runtime.Version(),
	}).Set(1.0)
}
