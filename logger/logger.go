package logger

import (
	"fmt"
	"os"
	"time"
)

func Fatal(message ...interface{}) {
	fmt.Print(time.Now().Format("2006/01/02 15:04:05"))
	fmt.Print(" \033[1;31m[Fatal]\033[0m ")
	fmt.Fprintln(os.Stdout, message...)
	os.Exit(1)
}

func Error(message ...interface{}) {
	fmt.Print(time.Now().Format("2006/01/02 15:04:05"))
	fmt.Print(" \033[1;31m[Error]\033[0m ")
	fmt.Fprintln(os.Stdout, message...)
}

func Info(message ...interface{}) {
	fmt.Print(time.Now().Format("2006/01/02 15:04:05"))
	fmt.Print(" \033[1;36m[Info]\033[0m ")
	fmt.Fprintln(os.Stdout, message...)
}

func Infof(format string, message ...interface{}) {
	fmt.Print(time.Now().Format("2006/01/02 15:04:05"))
	fmt.Print(" \033[1;36m[Info]\033[0m " + fmt.Sprintf(format, message...))
}

func Warning(message ...interface{}) {
	fmt.Print(time.Now().Format("2006/01/02 15:04:05"))
	fmt.Print(" \033[1;33m[Warn]\033[0m ")
	fmt.Fprintln(os.Stdout, message...)
}
