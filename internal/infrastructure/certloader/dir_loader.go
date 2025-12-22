package certloader

import (
	"context"
	"os"
	"path/filepath"

	"x509-watch/internal/entity"
	"x509-watch/internal/usecase"
)

type DirLoader struct {
	Root   string
	Logger usecase.Logger
}

func NewDirLoader(root string, logger usecase.Logger) *DirLoader {
	return &DirLoader{
		Root:   root,
		Logger: logger,
	}
}

func (l *DirLoader) LoadCertificates(ctx context.Context) ([]*entity.CertInfo, []*entity.CertError) {
	var certs []*entity.CertInfo
	var errs []*entity.CertError

	var walk func(path string)

	walk = func(path string) {
		select {
		case <-ctx.Done():
			errs = append(errs, entity.NewCertError(path, entity.ErrTypeUnknown, ctx.Err()))
			return
		default:
		}

		info, err := os.Stat(path)
		if err != nil {
			errs = append(errs, entity.NewCertError(path, entity.ErrTypeRead, err))
			return
		}

		if info.IsDir() {
			l.Logger.Debugf("Descending into directory %s", path)

			entries, err := os.ReadDir(path)
			if err != nil {
				errs = append(errs, entity.NewCertError(path, entity.ErrTypeRead, err))
				return
			}
			for _, e := range entries {
				walk(filepath.Join(path, e.Name()))
			}
			return
		}

		l.Logger.Debugf("Trying file %s", path)

		fl := NewFileLoader(path, l.Logger)
		cs, es := fl.LoadCertificates(ctx)
		certs = append(certs, cs...)
		errs = append(errs, es...)
	}

	walk(l.Root)

	return certs, errs
}
