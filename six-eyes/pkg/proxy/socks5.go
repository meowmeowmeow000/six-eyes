package proxy

import (
	"io"
	"log"
	"net"

	"github.com/six-eyes/six-eyes/pkg/desync"
)

type Socks5Server struct {
	addr string
	sm   *desync.StateMachine
}

func NewSocks5Server(addr string, sm *desync.StateMachine) *Socks5Server {
	return &Socks5Server{addr: addr, sm: sm}
}

func (s *Socks5Server) Start() error {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	log.Printf("[SIX EYES] SOCKS5 / Transparent Proxy listening on %s", s.addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *Socks5Server) handleConnection(client net.Conn) {
	defer client.Close()

	buf := make([]byte, 256)
	n, err := client.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return
	}
	client.Write([]byte{0x05, 0x00}) // No auth

	n, err = client.Read(buf)
	if err != nil || n < 4 || buf[1] != 0x01 {
		return // CONNECT only
	}

	target := "104.16.249.249:443"
	upstream, err := net.Dial("tcp", target)
	if err != nil {
		client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()

	client.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38})
	s.sm.RecordPacket(true)

	go io.Copy(upstream, client)
	io.Copy(client, upstream)
}
