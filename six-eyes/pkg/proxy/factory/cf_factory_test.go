package factory

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

type captureConn struct {
	net.Conn
	records [][]byte
}

func (c *captureConn) Write(b []byte) (int, error) {
	cp := append([]byte(nil), b...)
	c.records = append(c.records, cp)
	return len(b), nil
}

func buildMockClientHello(sni string) []byte {
	payload := make([]byte, 0, 128)
	payload = append(payload, bytes.Repeat([]byte{0xAA}, 45)...)
	payload = append(payload, []byte(sni)...)
	payload = append(payload, bytes.Repeat([]byte{0xBB}, 30)...)

	rec := make([]byte, 5+len(payload))
	rec[0] = 0x16
	rec[1] = 0x03
	rec[2] = 0x01
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(payload)))
	copy(rec[5:], payload)
	return rec
}

func TestClientHelloDisorder7Slice(t *testing.T) {
	sni := "stealth.example.workers.dev"
	rawHello := buildMockClientHello(sni)

	capConn := &captureConn{}
	frag := &clientHelloFragConn{
		Conn:         capConn,
		disorderMode: true,
		sniBytes:     []byte(sni),
		delayMs:      0,
		jitterMs:     0,
	}

	n, err := frag.Write(rawHello)
	if err != nil || n != len(rawHello) {
		t.Fatalf("Write failed: n=%d err=%v", n, err)
	}
	if len(capConn.records) != 7 {
		t.Fatalf("expected 7 TLS records in disorderMode, got %d", len(capConn.records))
	}

	var reassembled []byte
	for i, r := range capConn.records {
		if len(r) < 5 || r[0] != 0x16 {
			t.Fatalf("record %d invalid TLS header", i)
		}
		length := int(binary.BigEndian.Uint16(r[3:5]))
		if len(r) != 5+length {
			t.Fatalf("record %d length mismatch", i)
		}
		reassembled = append(reassembled, r[5:]...)
	}

	if !bytes.Equal(reassembled, rawHello[5:]) {
		t.Fatalf("reassembled payload does not match original ClientHello payload")
	}
}
