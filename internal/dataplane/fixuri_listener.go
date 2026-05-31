package dataplane

import "net"

type fixURIListener struct {
	net.Listener
}

func NewFixURIListener(ln net.Listener) net.Listener {
	return &fixURIListener{Listener: ln}
}

func (l *fixURIListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return NewFixURIConn(c), nil
}
