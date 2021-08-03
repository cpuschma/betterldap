package betterldap

import (
	"crypto/tls"
	"net"
)

type ConnectionOptions struct {
	TLSConfig *tls.Config
	Dialer    net.Dialer
}

func Dial(network, address string, opt ConnectionOptions) (*Conn, error) {
	conn, err := opt.Dialer.Dial(network, address)
	if err != nil {
		return nil, err
	}

	return NewConnection(conn), nil
}

func DialTLS(network, address string, opt ConnectionOptions) (*Conn, error) {
	conn, err := tls.DialWithDialer(
		&opt.Dialer,
		network,
		address,
		opt.TLSConfig,
	)
	if err != nil {
		return nil, err
	}

	return NewConnection(conn), nil
}
