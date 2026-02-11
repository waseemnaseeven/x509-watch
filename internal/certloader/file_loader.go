package certloader

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"os"
)

type FileLoader struct {
	Path   string
	Logger *slog.Logger
}

func NewFileLoader(path string, logger *slog.Logger) *FileLoader {
	return &FileLoader{
		Path:   path,
		Logger: logger,
	}
}

func (l *FileLoader) LoadCertificates(ctx context.Context) ([]*CertInfo, []*CertError) {
	select {
	case <-ctx.Done():
		return nil, []*CertError{NewCertError(l.Path, ErrTypeUnknown, ctx.Err())}
	default:
	}

	l.Logger.Debug("Loading certificates from file", "path", l.Path)

	f, err := os.Open(l.Path)
	if err != nil {
		return nil, []*CertError{NewCertError(l.Path, ErrTypeRead, err)}
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, []*CertError{NewCertError(l.Path, ErrTypeRead, err)}
	}

	var certs []*CertInfo
	var errs []*CertError

	rest := data
	seenPEM := false

	// PEM Parsing
	for {
		if len(rest) == 0 {
			break
		}

		// Try PEM file
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		seenPEM = true
		rest = remaining

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			errs = append(errs, NewCertError(l.Path, ErrTypeParse, err))
			continue
		}
		info := &CertInfo{
			FilePath:   l.Path,
			CommonName: cert.Subject.CommonName,
			Issuer:     cert.Issuer.CommonName,
			NotBefore:  cert.NotBefore,
			NotAfter:   cert.NotAfter,
		}
		certs = append(certs, info)

	}

	// DEM Parsing
	if !seenPEM {
		if len(data) == 0 {
			return nil, []*CertError{
				NewCertError(l.Path, ErrTypePEM, fmt.Errorf("empty file")),
			}
		}

		l.Logger.Debug("No PEM found, trying DER", "path", l.Path)

		// Try DER
		cert, err := x509.ParseCertificate(data)
		if err != nil {
			return nil, []*CertError{
				NewCertError(l.Path, ErrTypePEM, fmt.Errorf("not PEM nor DER X.509: %w", err)),
			}
		}

		// DER Success
		info := &CertInfo{
			FilePath:   l.Path,
			CommonName: cert.Subject.CommonName,
			Issuer:     cert.Issuer.CommonName,
			NotBefore:  cert.NotBefore,
			NotAfter:   cert.NotAfter,
		}
		return []*CertInfo{info}, nil
	}

	return certs, errs
}
