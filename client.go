package betterldap

import (
	"betterldap/internal/debug"
	"crypto/tls"
	"net"
)

type ConnectionOptions struct {
	TLSConfig *tls.Config
	Dialer    net.Dialer
}

var AutostartMsgProcessor = true

func Dial(network, address string, opt ConnectionOptions) (*Conn, error) {
	conn, err := opt.Dialer.Dial(network, address)
	if err != nil {
		return nil, err
	}

	newConn := NewConnection(conn)
	if AutostartMsgProcessor {
		startProcessor(newConn)
	}

	return newConn, nil
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

	newConn := NewConnection(conn)
	if AutostartMsgProcessor {
		startProcessor(newConn)
	}

	return newConn, nil
}

func startProcessor(conn *Conn) {
	go func() {
		err := conn.ReadIncomingMessages()
		if err != nil {
			_ = conn.Close()
		}

		for id := range conn.activeHandlers {
			conn.RemoveHandler(id)
			debug.Logf("removed still registered handler for (id=%d)", id)
		}
		debug.Logf("message processor exited (err=%v, IsClosing=%v)", err, conn.IsClosing())
	}()
}
