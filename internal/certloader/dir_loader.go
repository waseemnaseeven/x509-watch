package certloader

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
)

type DirLoader struct {
	Root   string
	Logger *slog.Logger
}

func NewDirLoader(root string, logger *slog.Logger) *DirLoader {
	return &DirLoader{
		Root:   root,
		Logger: logger,
	}
}

func (l *DirLoader) LoadCertificates(ctx context.Context) ([]*CertInfo, []*CertError) {
	var certs []*CertInfo
	var errs []*CertError

	err := filepath.WalkDir(l.Root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			errs = append(errs, NewCertError(path, ErrTypeRead, err))
			return nil
		}

		// Context cancellation
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Skip directories
		if d.IsDir() {
			return nil
		}

		// Load certificate
		fl := NewFileLoader(path, l.Logger)
		cs, es := fl.LoadCertificates(ctx)
		certs = append(certs, cs...)
		errs = append(errs, es...)

		return nil
	})

	// Fix: Handle both cancellation types
	if err != nil && err != context.Canceled && err != context.DeadlineExceeded {
		errs = append(errs, NewCertError(l.Root, ErrTypeUnknown, err))
	}

	return certs, errs
}
