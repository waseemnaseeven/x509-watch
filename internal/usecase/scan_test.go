package usecase

import (
	"context"
	"testing"
	"time"

	"x509-watch/internal/entity"
)

type fakeLoader struct {
	certs []*entity.CertInfo
	errs  []*entity.CertError
}

func (f *fakeLoader) LoadCertificates(ctx context.Context) ([]*entity.CertInfo, []*entity.CertError) {
	return f.certs, f.errs
}

type fakePublisher struct {
	calls int
}

func (f *fakePublisher) PublishCerts(certs []*entity.CertInfo, errs []*entity.CertError) {
	f.calls++
}

type fakeLogger struct{}

func (f *fakeLogger) Infof(format string, args ...any)  {}
func (f *fakeLogger) Errorf(format string, args ...any) {}
func (f *fakeLogger) Warnf(format string, args ...any)  {}
func (f *fakeLogger) Debugf(format string, args ...any) {}

func TestCertScanService_RunOnce(t *testing.T) {
	loader := &fakeLoader{
		certs: []*entity.CertInfo{
			{CommonName: "example.com"},
		},
	}
	pub := &fakePublisher{}
	log := &fakeLogger{}

	svc := &CertScanService{
		Loader:    loader,
		Publisher: pub,
		Logger:    log,
	}

	svc.RunOnce(context.Background())

	if pub.calls != 1 {
		t.Fatalf("expected publisher to be called once, got %d", pub.calls)
	}
}

func TestCertScanService_RunPeriodic_Stop(t *testing.T) {
	loader := &fakeLoader{}
	pub := &fakePublisher{}
	log := &fakeLogger{}

	svc := &CertScanService{
		Loader:    loader,
		Publisher: pub,
		Logger:    log,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go svc.RunPeriodic(ctx, 10*time.Millisecond)

	time.Sleep(25 * time.Millisecond)
	cancel()
	if pub.calls < 2 {
		t.Fatalf("expected at least 2 scan runs, got %d", pub.calls)
	}
}
