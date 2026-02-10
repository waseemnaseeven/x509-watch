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
				return nil, []*CertError{NewCertError(l.Path, ErrTypeParse, err)}
			}
			info := &CertInfo{
				CommonName: cert.Subject.CommonName,
				Issuer:     cert.Issuer.CommonName,
				NotBefore:  cert.NotBefore,
				NotAfter:   cert.NotAfter,
				FilePath:   l.Path,
			}
			certs = append(certs, info)

		default:
			l.Logger.Debug("Ignoring PEM block type", "type", block.Type, "path", l.Path)
		}
	}

	if seenPEM {
		if len(certs) == 0 {
			return nil, []*CertError{
				NewCertError(l.Path, ErrTypePEM, fmt.Errorf("no CERTIFICATE PEM block found")),
			}
		}
		return certs, nil
	}

	l.Logger.Debug("No PEM blocks found, trying DER parse", "path", l.Path)

	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, []*CertError{
			NewCertError(l.Path, ErrTypePEM, fmt.Errorf("not PEM nor DER X.509: %w", err)),
		}
	}

	info := &CertInfo{
		CommonName: cert.Subject.CommonName,
		Issuer:     cert.Issuer.CommonName,
		NotBefore:  cert.NotBefore,
		NotAfter:   cert.NotAfter,
		FilePath:   l.Path,
	}

	return []*CertInfo{info}, nil
}
