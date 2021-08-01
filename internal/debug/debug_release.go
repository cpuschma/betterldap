//go:build !debug
// +build !debug

package debug

func Log(args ...interface{}) {}

func Logf(f string, args ...interface{}) {}
