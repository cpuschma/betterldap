package debug

import (
	"log"
	"os"
)

var logger = log.New(os.Stdout, "[DEBUG] ", 0)

func Log(args ...interface{}) {
	logger.Println(args...)
}

func Logf(f string, args ...interface{}) {
	logger.Printf(f, args...)
}
