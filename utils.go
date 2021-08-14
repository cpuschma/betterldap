package betterldap

import (
	"errors"
	"math/rand"
	"time"
)

var (
	ErrMissingChild = errors.New("missing ber packet child")
	ErrCastFailed   = errors.New("cast to type failed")
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func randomBytes(len int) []byte {
	buff := make([]byte, len)
	for i := 0; i < len; i++ {
		buff[i] = byte(rand.Intn(256))
	}

	return buff
}
