package httpserver

import (
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"x509-watch/internal/usecase"
)

type Server struct {
	Address string
	Logger  usecase.Logger
}

func NewServer(addr string, logger usecase.Logger) *Server {
	return &Server{
		Address: addr,
		Logger:  logger,
	}
}

func (s *Server) Serve(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	srv := &http.Server{
		Addr:    s.Address,
		Handler: mux,
	}

	// Graceful shutdown
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	s.Logger.Infof("HTTP server listening on %s", s.Address)
	err := srv.ListenAndServe()
	if err == http.ErrServerClosed {
		s.Logger.Infof("HTTP server shut down")
		return nil
	}
	return err
}
