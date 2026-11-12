package proxy

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/meowmeowmeow000/six-eyes/pkg/proxy/pool"
	"github.com/meowmeowmeow000/six-eyes/pkg/telemetry"
)

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

func StartSOCKS5(ctx context.Context, listenAddr string, warmPool *pool.WarmPool) error {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	telemetry.Log.Info("SOCKS5 Zero-Alloc Intake Listening", slog.String("addr", listenAddr))

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		go handleSOCKS5(ctx, clientConn, warmPool)
	}
}

func handleSOCKS5(ctx context.Context, client net.Conn, warmPool *pool.WarmPool) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	var hdr [260]byte
	if _, err := io.ReadFull(client, hdr[:2]); err != nil || hdr[0] != 0x05 {
		return
	}
	nMethods := int(hdr[1])
	if _, err := io.ReadFull(client, hdr[:nMethods]); err != nil {
		return
	}
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	if _, err := io.ReadFull(client, hdr[:4]); err != nil || hdr[0] != 0x05 || hdr[1] != 0x01 {
		_, _ = client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var targetHost string
	switch hdr[3] {
	case 0x01:
		if _, err := io.ReadFull(client, hdr[:4]); err != nil {
			return
		}
		targetHost = net.IP(hdr[:4]).String()
	case 0x03:
		if _, err := io.ReadFull(client, hdr[:1]); err != nil {
			return
		}
		dLen := int(hdr[0])
		if _, err := io.ReadFull(client, hdr[:dLen]); err != nil {
			return
		}
		targetHost = string(hdr[:dLen])
	case 0x04:
		if _, err := io.ReadFull(client, hdr[:16]); err != nil {
			return
		}
		targetHost = net.IP(hdr[:16]).String()
	default:
		return
	}
	if _, err := io.ReadFull(client, hdr[:2]); err != nil {
		return
	}
	targetPort := binary.BigEndian.Uint16(hdr[:2])
	_ = client.SetDeadline(time.Time{})

	remoteStream, err := warmPool.GetStream(ctx)
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remoteStream.Close()

	hostBytes := []byte(targetHost)
	if len(hostBytes) == 0 || len(hostBytes) > 255 {
		return
	}
	frame := make([]byte, 1+len(hostBytes)+2)
	frame[0] = byte(len(hostBytes))
	copy(frame[1:], hostBytes)
	binary.BigEndian.PutUint16(frame[1+len(hostBytes):], targetPort)

	_ = remoteStream.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := remoteStream.Write(frame); err != nil {
		_, _ = client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	_ = remoteStream.SetWriteDeadline(time.Time{})

	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	telemetry.ActiveStreams.Add(1)
	defer telemetry.ActiveStreams.Add(-1)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		bufPtr := bufPool.Get().(*[]byte)
		defer bufPool.Put(bufPtr)
		n, _ := io.CopyBuffer(remoteStream, client, *bufPtr)
		telemetry.TotalBytesTx.Add(uint64(n))
	}()

	go func() {
		defer wg.Done()
		bufPtr := bufPool.Get().(*[]byte)
		defer bufPool.Put(bufPtr)
		n, _ := io.CopyBuffer(client, remoteStream, *bufPtr)
		telemetry.TotalBytesRx.Add(uint64(n))
		if tcpC, ok := client.(*net.TCPConn); ok {
			_ = tcpC.CloseWrite()
		}
		_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	}()
	wg.Wait()
}
