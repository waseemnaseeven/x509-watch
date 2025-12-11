package config

import (
	"flag"
	"time"
)

type Config struct {
	ListenAddr   string
	CertFile     string
	CertDir      string
	ScanInterval time.Duration
}

func FromFlags() *Config {
	cfg := &Config{}

	flag.StringVar(&cfg.ListenAddr, "listen", ":9101", "HTTP listen address (host:port)")
	flag.StringVar(&cfg.CertFile, "cert-file", "", "Path to a certificate file (PEM/DER)")
	flag.StringVar(&cfg.CertDir, "cert-dir", "", "Path to a directory containing certificates")
	flag.DurationVar(&cfg.ScanInterval, "interval", 0, "Scan interval (0 = only once at startup)")

	flag.Parse()

	return cfg
}

type ErrConfig string

func (e ErrConfig) Error() string { return string(e) }

func (c *Config) Validate() error {
	switch {
	case c.CertFile == "" && c.CertDir == "":
		return ErrConfig("either --cert-file or --cert-dir must be set")
	case c.CertFile != "" && c.CertDir != "":
		return ErrConfig("only one of --cert-file or --cert-dir can be set")
	}
	return nil
}
