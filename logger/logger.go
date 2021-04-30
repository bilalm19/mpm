package logger

import "log"

func Fatal(message interface{}) {
	log.Fatalf("\033[1;31m[Fatal]\033[0m %s\n", message)
}

func Error(message interface{}) {
	log.Printf("\033[1;31m[Error]\033[0m %s\n", message)
}

func Info(message interface{}) {
	log.Printf("\033[1;36m[Info]\033[0m %s\n", message)
}

func Infof(message interface{}) {
	log.Printf("\033[1;36m[Info]\033[0m %+v", message)
}
