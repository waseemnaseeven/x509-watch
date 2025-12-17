package usecase

import (
	"context"
	"x509-watch/internal/entity"
)

// Charging Cert from a source (dir, file...)
type CertLoader interface {
	LoadCertificates(ctx context.Context) ([]*entity.CertInfo, []*entity.CertError)
}

// Publishing Metrics
type MetricsPublisher interface {
	PublishCerts(certs []*entity.CertInfo, errs []*entity.CertError)
}

// Logger
type Logger interface {
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
	Debugf(format string, args ...any)
}
