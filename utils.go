package betterldap

import (
	"errors"
)

var (
	ErrMissingChild = errors.New("missing ber packet child")
	ErrCastFailed   = errors.New("cast to type failed")
)
