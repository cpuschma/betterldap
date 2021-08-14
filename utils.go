package betterldap

import (
	"errors"
	"math/rand"
)

var (
	ErrMissingChild = errors.New("missing ber packet child")
	ErrCastFailed   = errors.New("cast to type failed")
)

func randomBytes(len int) []byte {
	buff := make([]byte, len)
	rand.Read(buff)
	return buff
}
