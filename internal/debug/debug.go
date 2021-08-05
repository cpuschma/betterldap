//go:build debug
// +build debug

package debug

import (
	"log"
	"os"
	"runtime"
)

var logger = log.New(os.Stdout, "[DEBUG] ", log.LstdFlags)

func Log(args ...interface{}) {
	args = append([]interface{}{getFrame(1).Function}, args...)
	logger.Println(args...)
}

func Logf(f string, args ...interface{}) {
	args = append([]interface{}{getFrame(1).Function}, args...)
	f = "%s " + f
	logger.Printf(f, args...)
}

func getFrame(skipFrames int) runtime.Frame {
	// We need the frame at index skipFrames+2, since we never want runtime.Callers and getFrame
	targetFrameIndex := skipFrames + 2

	// Set size to targetFrameIndex+2 to ensure we have room for one more caller than we need
	programCounters := make([]uintptr, targetFrameIndex+2)
	n := runtime.Callers(0, programCounters)

	frame := runtime.Frame{Function: "unknown"}
	if n > 0 {
		frames := runtime.CallersFrames(programCounters[:n])
		for more, frameIndex := true, 0; more && frameIndex <= targetFrameIndex; frameIndex++ {
			var frameCandidate runtime.Frame
			frameCandidate, more = frames.Next()
			if frameIndex == targetFrameIndex {
				frame = frameCandidate
			}
		}
	}

	return frame
}
