package usecase

import (
	"context"
	"time"
)

type CertScanService struct {
	Loader    CertLoader
	Publisher MetricsPublisher
	Logger    Logger
}

func (s *CertScanService) RunOnce(ctx context.Context) {
	start := time.Now()
	s.Logger.Infof("Starting certificate scan...")

	certs, errs := s.Loader.LoadCertificates(ctx)
	s.Publisher.PublishCerts(certs, errs)
	s.Logger.Infof("Scan done in %s: %d certs, %d errors", time.Since(start), len(certs), len(errs))
}

// Periodic Scan with ticker and recover
func (s *CertScanService) RunPeriodic(ctx context.Context, interval time.Duration) {
	defer func() {
		if r := recover(); r != nil {
			s.Logger.Errorf("panic recovered in RunPeriodic: %v", r)
		}
	}()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.Logger.Infof("Stopping periodic scan")
			return
		case <-ticker.C:
			s.RunOnce(ctx)
		}
	}
}
