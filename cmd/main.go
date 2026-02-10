package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"x509-watch/internal/certloader"
	"x509-watch/internal/metrics"
)

var (
	version  = "dev"
	revision = "unknown"
)

// loader is the common interface for FileLoader and DirLoader.
type loader interface {
	LoadCertificates(ctx context.Context) ([]*certloader.CertInfo, []*certloader.CertError)
}

// === Config ===

type config struct {
	listenAddr   string
	certFile     string
	certDir      string
	scanInterval time.Duration
	logLevel     string
}

func parseFlags() config {
	var cfg config
	var showHelp bool

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options]\n\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Println()
		fmt.Fprintf(flag.CommandLine.Output(), `Examples:
	%s --cert-file=/path/to/cert.pem
	%s --cert-dir=/etc/vault/certs --interval=1m --log-level=debug `, os.Args[0], os.Args[0])
	}

	flag.StringVar(&cfg.listenAddr, "listen", ":9101", "HTTP listen address (host:port)")
	flag.StringVar(&cfg.certFile, "cert-file", "", "Path to a certificate file (PEM/DER)")
	flag.StringVar(&cfg.certDir, "cert-dir", "", "Path to a directory containing certificates")
	flag.DurationVar(&cfg.scanInterval, "interval", 0, "Scan interval (0 = only once at startup)")
	flag.StringVar(&cfg.logLevel, "log-level", "info", "Log level: debug, info, warn, error")
	flag.BoolVar(&showHelp, "help", false, "Show help and exit")
	flag.BoolVar(&showHelp, "h", false, "Show help and exit (shorthand)")

	flag.Parse()

	if showHelp {
		flag.Usage()
		os.Exit(0)
	}

	return cfg
}

func (c config) validate() error {
	switch {
	case c.certFile == "" && c.certDir == "":
		return fmt.Errorf("either --cert-file or --cert-dir must be set")
	case c.certFile != "" && c.certDir != "":
		return fmt.Errorf("only one of --cert-file or --cert-dir can be set")
	case c.scanInterval < 0:
		return fmt.Errorf("interval must be greater or equal to 0")
	}
	switch strings.ToLower(c.logLevel) {
	case "debug", "info", "warn", "warning", "error":
	default:
		return fmt.Errorf("log-level must be one of: debug, info, warn, error")
	}
	return nil
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// === Scan ===

func scanOnce(ctx context.Context, l loader, pub *metrics.PromPublisher, logger *slog.Logger) {
	start := time.Now()
	logger.Info("Starting certificate scan...")

	certs, errs := l.LoadCertificates(ctx)
	pub.PublishCerts(certs, errs)
	logger.Info(fmt.Sprintf("Scan done in %s: %d certs, %d errors", time.Since(start), len(certs), len(errs)))
}

func scanPeriodic(ctx context.Context, interval time.Duration, l loader, pub *metrics.PromPublisher, logger *slog.Logger) {
	scanOnceSafe(ctx, l, pub, logger)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("Stopping periodic scan")
			return
		case <-ticker.C:
			scanOnceSafe(ctx, l, pub, logger)
		}
	}
}

func scanOnceSafe(ctx context.Context, l loader, pub *metrics.PromPublisher, logger *slog.Logger) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error(fmt.Sprintf("panic recovered in scan: %v", r))
		}
	}()
	scanOnce(ctx, l, pub, logger)
}

// === HTTP Server ===

func serve(ctx context.Context, addr string, logger *slog.Logger) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	logger.Info(fmt.Sprintf("HTTP server listening on %s", addr))
	err := srv.ListenAndServe()
	if err == http.ErrServerClosed {
		logger.Info("HTTP server shut down")
		return nil
	}
	return err
}

func main() {
	cfg := parseFlags()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLevel(cfg.logLevel),
	}))

	if err := cfg.validate(); err != nil {
		logger.Error("invalid config", "error", err)
		os.Exit(1)
	}

	metrics.SetBuildInfo(version, revision)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var l loader
	if cfg.certFile != "" {
		logger.Info("Using file loader", "path", cfg.certFile)
		l = certloader.NewFileLoader(cfg.certFile, logger)
	} else {
		logger.Info("Using dir loader", "path", cfg.certDir)
		l = certloader.NewDirLoader(cfg.certDir, logger)
	}

	pub := metrics.NewPromPublisher(time.Now)

	if cfg.scanInterval > 0 {
		logger.Info("Starting periodic scan", "interval", cfg.scanInterval)
		go scanPeriodic(ctx, cfg.scanInterval, l, pub, logger)
	} else {
		scanOnce(ctx, l, pub, logger)
	}

	if err := serve(ctx, cfg.listenAddr, logger); err != nil {
		logger.Error("http server error", "error", err)
		os.Exit(1)
	}
}
