package log

import (
	stdlog "log"
	"os"

	"x509-watch/internal/usecase"
)

type LogLevel int

const (
	LevelInfo LogLevel = iota
	LevelDebug
)

type Logger struct {
	logger *stdlog.Logger
	level  LogLevel
}

func NewLogger() usecase.Logger {
	level := LevelInfo
	if os.Getenv("X509_WATCH_DEBUG") == "1" {
		level = LevelDebug
	}

	return &Logger{
		logger: stdlog.New(os.Stdout, "[x509-watch] ", stdlog.LstdFlags|stdlog.Lmsgprefix),
		level:  level,
	}
}

func (l *Logger) Infof(format string, args ...any) {
	l.logger.Printf("INFO: "+format, args...)
}

func (l *Logger) Errorf(format string, args ...any) {
	l.logger.Printf("ERROR: "+format, args...)
}

func (l *Logger) Debugf(format string, args ...any) {
	if l.level >= LevelDebug {
		l.logger.Printf("DEBUG: "+format, args...)
	}
}
