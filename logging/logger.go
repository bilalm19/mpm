package logging

import (
	"fmt"
	"os"
	"time"
)

type Level uint8

const (
	Debug Level = iota
	Info
	Warn
	Error
	Fatal
)

type Logger struct {
	LogLevel Level
}

func New(level Level) Logger {
	return Logger{
		LogLevel: level,
	}
}

func (l *Logger) Fatal(message ...interface{}) {
	annotate("1m[Fatal]", message...)
	os.Exit(1)
}

func (l *Logger) Fatalf(format string, message ...interface{}) {
	annotatef("1m[Fatal]", format, message...)
	os.Exit(1)
}

func (l *Logger) Error(message ...interface{}) {
	if l.LogLevel <= Error {
		annotate("1m[Error]", message...)
	}
}

func (l *Logger) Errorf(format string, message ...interface{}) {
	if l.LogLevel <= Error {
		annotatef("1m[Error]", format, message...)
	}
}

func (l *Logger) Info(message ...interface{}) {
	if l.LogLevel <= Info {
		annotate("6m[Info]", message...)
	}
}

func (l *Logger) Infof(format string, message ...interface{}) {
	if l.LogLevel <= Info {
		annotatef("6m[Info]", format, message...)
	}
}

func (l *Logger) Warn(message ...interface{}) {
	if l.LogLevel <= Warn {
		annotate("3m[Warn]", message...)
	}
}

func (l *Logger) Warnf(format string, message ...interface{}) {
	if l.LogLevel <= Warn {
		annotatef("3m[Warn]", format, message...)
	}
}

func (l *Logger) Debug(message ...interface{}) {
	if l.LogLevel == Debug {
		annotate("5m[Debug]", message...)
	}
}

func (l *Logger) Debugf(format string, message ...interface{}) {
	if l.LogLevel == Debug {
		annotatef("5m[Debug]", format, message...)
	}
}

func annotate(annotation string, message ...interface{}) {
	fmt.Printf("%v \033[1;3%s\033[0m ", time.Now().Format("2006/01/02 15:04:05"), annotation)
	fmt.Fprintln(os.Stdout, message...)
}

func annotatef(annotation string, format string, message ...interface{}) {
	fmt.Printf("%v \033[1;3%s\033[0m %s",
		time.Now().Format("2006/01/02 15:04:05"),
		annotation, fmt.Sprintf(format, message...))
}
