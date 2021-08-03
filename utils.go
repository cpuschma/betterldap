package betterldap

import (
	"errors"
	"fmt"
	ber "github.com/go-asn1-ber/asn1-ber"
)

var (
	ErrMissingChild = errors.New("missing ber packet child")
	ErrCastFailed   = errors.New("cast to type failed")
)

func parseString(packet *ber.Packet, i int, dst *string) error {
	if err := checkMissingIndex(packet, i); err != nil {
		return err
	}

	*dst = packet.Children[i].Data.String()
	return nil
}

func parseInt64(packet *ber.Packet, i int, dst *int64) error {
	if err := checkMissingIndex(packet, i); err != nil {
		return err
	}

	var ok bool
	*dst, ok = packet.Children[i].Value.(int64)
	if !ok {
		return ErrCastFailed
	}

	return nil
}

func parseInt32(packet *ber.Packet, i int, dst *int32) error {
	if err := checkMissingIndex(packet, i); err != nil {
		return err
	}

	var ok bool
	*dst, ok = packet.Children[i].Value.(int32)
	if !ok {
		return ErrCastFailed
	}

	return nil
}

func checkMissingIndex(packet *ber.Packet, i int) error {
	if packet.Children[i] == nil {
		return fmt.Errorf("%w: index %d", ErrMissingChild, i)
	}

	return nil
}
