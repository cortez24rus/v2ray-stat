package logger

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// Level represents a logging level.
type Level uint8

const (
	LevelPanic Level = iota
	LevelFatal
	LevelError
	LevelWarn
	LevelInfo
	LevelDebug
	LevelTrace
	LevelNone
)

// FormatLevel converts a Level to its string representation.
func FormatLevel(level Level) string {
	switch level {
	case LevelTrace:
		return "TRACE"
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	case LevelFatal:
		return "FATAL"
	case LevelPanic:
		return "PANIC"
	case LevelNone:
		return "NONE"
	default:
		return "UNKNOWN"
	}
}

// ParseLevel converts a string to a Level.
func ParseLevel(level string) (Level, error) {
	switch strings.ToLower(level) {
	case "trace":
		return LevelTrace, nil
	case "debug":
		return LevelDebug, nil
	case "info":
		return LevelInfo, nil
	case "warn", "warning":
		return LevelWarn, nil
	case "error":
		return LevelError, nil
	case "fatal":
		return LevelFatal, nil
	case "panic":
		return LevelPanic, nil
	case "none":
		return LevelNone, nil // Устанавливаем LevelNone вместо Level(255)
	default:
		return LevelNone, fmt.Errorf("unknown log level: %s", level)
	}
}

// Logger is a simple logger with level-based logging.
type Logger struct {
	writer io.Writer
	level  Level
}

// NewLogger creates a new Logger with the specified level and writer.
func NewLogger(level string, writer io.Writer) (*Logger, error) {
	lvl, err := ParseLevel(level)
	if err != nil {
		return nil, err
	}
	return &Logger{
		writer: writer,
		level:  lvl,
	}, nil
}

// log writes a log message if the specified level is enabled.
func (l *Logger) log(level Level, msg string, args ...any) {
	if l.level == LevelNone || level > l.level {
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] %s", FormatLevel(level), msg)
	for i := 0; i < len(args); i += 2 {
		if i+1 < len(args) {
			fmt.Fprintf(&b, ", %v=%v", args[i], args[i+1])
		}
	}
	fmt.Fprintln(&b)
	l.writer.Write([]byte(b.String()))
	if level == LevelFatal {
		os.Exit(1)
	}
	if level == LevelPanic {
		panic(b.String())
	}
}

// Trace logs a message at TRACE level.
func (l *Logger) Trace(msg string, args ...any) {
	l.log(LevelTrace, msg, args...)
}

// Debug logs a message at DEBUG level.
func (l *Logger) Debug(msg string, args ...any) {
	l.log(LevelDebug, msg, args...)
}

// Info logs a message at INFO level.
func (l *Logger) Info(msg string, args ...any) {
	l.log(LevelInfo, msg, args...)
}

// Warn logs a message at WARN level.
func (l *Logger) Warn(msg string, args ...any) {
	l.log(LevelWarn, msg, args...)
}

// Error logs a message at ERROR level.
func (l *Logger) Error(msg string, args ...any) {
	l.log(LevelError, msg, args...)
}

// Fatal logs a message at FATAL level and exits.
func (l *Logger) Fatal(msg string, args ...any) {
	l.log(LevelFatal, msg, args...)
}

// Panic logs a message at PANIC level and panics.
func (l *Logger) Panic(msg string, args ...any) {
	l.log(LevelPanic, msg, args...)
}
