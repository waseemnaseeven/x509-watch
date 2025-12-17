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

// RunPeriodic triggers an initial scan and then keeps scanning at the given interval until ctx is cancelled.
func (s *CertScanService) RunPeriodic(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		s.RunOnce(ctx)
		return
	}

	s.runOnceSafe(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
			case <-ctx.Done():
				s.Logger.Infof("Stopping periodic scan")
				return
			case <-ticker.C:
				s.runOnceSafe(ctx)
		}
	}
}

func (s *CertScanService) runOnceSafe(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			s.Logger.Errorf("panic recovered in RunPeriodic: %v", r)
		}
	}()
	s.RunOnce(ctx)
}
