package config

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

type Config struct {
	ListenAddr   	string
	CertFile     	string
	CertDir      	string
	ScanInterval 	time.Duration
	LogLevel     	string
	ShowHelp		bool	
}

func FromFlags() *Config {
	cfg := &Config{}

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options]\n\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), `
			Examples:
			%s --cert-file=/path/to/cert.pem
			%s --cert-dir=/etc/vault/certs --interval=1m --log-level=debug
			`, os.Args[0], os.Args[0])
	}


	flag.StringVar(&cfg.ListenAddr, "listen", ":9101", "HTTP listen address (host:port)")
	flag.StringVar(&cfg.CertFile, "cert-file", "", "Path to a certificate file (PEM/DER)")
	flag.StringVar(&cfg.CertDir, "cert-dir", "", "Path to a directory containing certificates")
	flag.DurationVar(&cfg.ScanInterval, "interval", 0, "Scan interval (0 = only once at startup)")
	flag.StringVar(&cfg.LogLevel, "log-level", "info", "Log level: debug, info, warn, error")
	flag.BoolVar(&cfg.ShowHelp, "help", false, "Show help and exit")
	flag.BoolVar(&cfg.ShowHelp, "h", false, "Show help and exit (shorthand)")

	flag.Parse()

	if cfg.ShowHelp {
		flag.Usage()
		os.Exit(0)
	}

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
		case c.ScanInterval < 0:
			return ErrConfig("interval must be greater or equal to 0")
	}
	switch strings.ToLower(c.LogLevel) {
		case "debug", "info", "warn", "warning", "error":
	default:
		return ErrConfig("log-level must be one of: debug, info, warn, error")
	}
	return nil
}
