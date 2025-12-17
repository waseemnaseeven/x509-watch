package certloader

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"x509-watch/internal/entity"
	"x509-watch/internal/usecase"
)

type FileLoader struct {
	Path   string
	Logger usecase.Logger
}

func NewFileLoader(path string, logger usecase.Logger) *FileLoader {
	return &FileLoader{
		Path:   path,
		Logger: logger,
	}
}

func (l *FileLoader) LoadCertificates(ctx context.Context) ([]*entity.CertInfo, []*entity.CertError) {
	select {
		case <-ctx.Done():
			return nil, []*entity.CertError{entity.NewCertError(l.Path, entity.ErrTypeUnknown, ctx.Err())}
		default:
	}

	l.Logger.Debugf("Loading certificates from file %s", l.Path)

	f, err := os.Open(l.Path)
	if err != nil {
		return nil, []*entity.CertError{entity.NewCertError(l.Path, entity.ErrTypeRead, err)}
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, []*entity.CertError{entity.NewCertError(l.Path, entity.ErrTypeRead, err)}
	}
)
	var certs []*entity.CertInfo
	rest := data
	seenPEM := false

	for {
		if len(rest) == 0 {
			break
		}

		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		seenPEM = true

		switch block.Type {
			case "CERTIFICATE":
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					return nil, []*entity.CertError{entity.NewCertError(l.Path, entity.ErrTypeParse, err)}
				}
				info := &entity.CertInfo{
					CommonName: cert.Subject.CommonName,
					Issuer:     cert.Issuer.CommonName,
					NotBefore:  cert.NotBefore,
					NotAfter:   cert.NotAfter,
					FilePath:   l.Path,
				}
				certs = append(certs, info)

			default:
				l.Logger.Debugf("Ignoring PEM block type %s in %s", block.Type, l.Path)
		}
	}

	if seenPEM {
		if len(certs) == 0 {
			return nil, []*entity.CertError{
				entity.NewCertError(l.Path, entity.ErrTypePEM, fmt.Errorf("no CERTIFICATE PEM block found")),
			}
		}
		return certs, nil
	}

	l.Logger.Debugf("No PEM blocks found in %s, trying DER parse", l.Path)

	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, []*entity.CertError{
			entity.NewCertError(l.Path, entity.ErrTypePEM, fmt.Errorf("not PEM nor DER X.509: %w", err)),
		}
	}

	info := &entity.CertInfo{
		CommonName: cert.Subject.CommonName,
		Issuer:     cert.Issuer.CommonName,
		NotBefore:  cert.NotBefore,
		NotAfter:   cert.NotAfter,
		FilePath:   l.Path,
	}

	return []*entity.CertInfo{info}, nil
}
