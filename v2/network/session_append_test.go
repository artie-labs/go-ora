package network

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sijms/go-ora/v2/configurations"
	"github.com/sijms/go-ora/v2/trace"
)

// streamConn serves a fixed byte stream to reads, in pieces of at most step bytes, as a socket does, and discards
// writes.
type streamConn struct {
	net.Conn
	data   []byte
	step   int
	writes int
}

func (c *streamConn) Read(b []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := len(b)
	if n > len(c.data) {
		n = len(c.data)
	}
	if n > c.step {
		n = c.step
	}
	copy(b, c.data[:n])
	c.data = c.data[n:]
	return n, nil
}

func (c *streamConn) Write(b []byte) (int, error) {
	c.writes++
	return len(b), nil
}

func (c *streamConn) SetReadDeadline(time.Time) error  { return nil }
func (c *streamConn) SetWriteDeadline(time.Time) error { return nil }

// packet frames payload as a TNS packet of type typ after the handshake: a 4-byte length, the type, a flag, a 2-byte
// checksum and, for a data packet, 2 bytes of data flags.
func packet(typ PacketType, payload []byte) []byte {
	header := make([]byte, 8, 10)
	if typ == DATA {
		header = header[:10]
	}
	binary.BigEndian.PutUint32(header, uint32(len(header)+len(payload)))
	header[4] = byte(typ)
	return append(header, payload...)
}

// dataPackets splits payload into data packets of at most size payload bytes each.
func dataPackets(payload []byte, size int) []byte {
	var out []byte
	for len(payload) > 0 {
		n := size
		if n > len(payload) {
			n = len(payload)
		}
		out = append(out, packet(DATA, payload[:n])...)
		payload = payload[n:]
	}
	return out
}

func newStreamSession(stream []byte, step int) (*Session, *streamConn) {
	session := NewSession(&configurations.ConnectionConfig{}, trace.NilTracer())
	session.Context.handshakeComplete = true
	session.Context.Version = 315
	conn := &streamConn{data: stream, step: step}
	session.conn = conn
	session.reader = bufio.NewReaderSize(conn, read_buffer_size)
	return session, conn
}

// clr encodes value as a CLR in chunks of at most chunk bytes, with 4-byte chunk lengths when big is set.
func clr(value []byte, chunk int, big bool) []byte {
	if len(value) < 0xFD && chunk >= len(value) {
		return append([]byte{byte(len(value))}, value...)
	}
	out := []byte{0xFE}
	for len(value) > 0 {
		n := chunk
		if n > len(value) {
			n = len(value)
		}
		if big {
			out = append(out, 4, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
		} else {
			out = append(out, byte(n))
		}
		out = append(out, value[:n]...)
		value = value[n:]
	}
	return append(out, 0)
}

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i/251)
	}
	return b
}

func TestAppendClr(t *testing.T) {
	{
		// Values of every shape, split into packets of many sizes, read as GetClr reads them, and the bytes after
		// them read as before. A slice read before the value keeps its bytes.
		prefix, suffix := []byte("before"), []byte("after the value")
		for _, c := range []struct {
			value []byte
			chunk int
			big   bool
		}{
			{[]byte("short"), 0xFF, false},
			{pattern(0xFD), 0xFD, false},
			{pattern(1000), 0xFC, false},
			{pattern(100_000), 32 << 10, true},
			{pattern(300_000), 8191, true},
		} {
			for _, size := range []int{1, 2, 7, 64, 255, 256, 257, 8 << 10, 1 << 20} {
				stream := append(append(append([]byte{}, prefix...), clr(c.value, c.chunk, c.big)...), suffix...)
				for _, appendTo := range []bool{false, true} {
					session, _ := newStreamSession(dataPackets(stream, size), 3000)
					session.UseBigClrChunks = c.big
					held, err := session.GetBytes(len(prefix))
					if err != nil {
						t.Fatal(err)
					}
					var got []byte
					if appendTo {
						got, err = session.AppendClr([]byte("x"))
						got = got[1:]
					} else {
						got, err = session.GetClr()
					}
					if err != nil {
						t.Fatalf("%d-byte value in %d-byte packets: %v", len(c.value), size, err)
					}
					if !bytes.Equal(got, c.value) {
						t.Fatalf("%d-byte value in %d-byte packets: wrong bytes", len(c.value), size)
					}
					if rest, err := session.GetBytes(len(suffix)); err != nil || !bytes.Equal(rest, suffix) {
						t.Fatalf("%d-byte value in %d-byte packets: read %q, %v after it", len(c.value), size, rest, err)
					}
					if !bytes.Equal(held, prefix) {
						t.Fatalf("%d-byte value in %d-byte packets: a slice read before it changed", len(c.value), size)
					}
					// The input buffer holds a packet or so, not the value.
					if appendTo && len(c.value) > 2*size && len(session.inBuffer) > size+len(suffix) {
						t.Fatalf("%d-byte value in %d-byte packets: input buffer grew to %d", len(c.value), size, len(session.inBuffer))
					}
				}
			}
		}
	}
	{
		// NULLs and an empty chunked value leave dst as it is.
		for _, stream := range [][]byte{{0}, {0xFF}, {0xFD}, {0xFE, 0}} {
			session, _ := newStreamSession(dataPackets(stream, 1), 1)
			if got, err := session.AppendClr([]byte("x")); err != nil || string(got) != "x" {
				t.Fatalf("% x: got %q, %v", stream, got, err)
			}
		}
	}
	{
		// A connection that ends inside a value fails the read.
		stream := dataPackets(clr(pattern(50_000), 32<<10, true), 4096)
		session, _ := newStreamSession(stream[:len(stream)/2], 1<<20)
		session.UseBigClrChunks = true
		if _, err := session.AppendClr(nil); err == nil {
			t.Fatal("read of a truncated value succeeded")
		}
	}
	{
		// A marker inside a value fails the read with ErrConnReset, and the error that follows it is left for the
		// caller to read, not appended to the value.
		value := clr(pattern(50_000), 32<<10, true)
		stream := dataPackets(value[:20_000], 4096)
		stream = append(stream, packet(MARKER, []byte{1, 0, 2})...)
		stream = append(stream, packet(MARKER, []byte{1, 0, 2})...)
		stream = append(stream, packet(DATA, []byte("the error"))...)
		session, conn := newStreamSession(stream, 1<<20)
		session.UseBigClrChunks = true
		got, err := session.AppendClr(nil)
		if !errors.Is(err, ErrConnReset) {
			t.Fatalf("got %v, want ErrConnReset", err)
		}
		if bytes.Contains(got, []byte("the error")) {
			t.Fatal("the error was appended to the value")
		}
		if conn.writes != 1 {
			t.Fatalf("sent %d packets, want the reset marker", conn.writes)
		}
		if rest, err := session.GetBytes(len("the error")); err != nil || string(rest) != "the error" {
			t.Fatalf("read %q, %v after the marker", rest, err)
		}
	}
}

func BenchmarkAppendClr(b *testing.B) {
	// An 8 MiB LOB read: chunks of 32 KiB in 8 KiB packets.
	value := pattern(8 << 20)
	stream := dataPackets(clr(value, 32<<10, true), 8<<10)
	for _, appendTo := range []bool{false, true} {
		name := "GetClr"
		if appendTo {
			name = "AppendClr"
		}
		b.Run(name, func(b *testing.B) {
			dst := make([]byte, 0, len(value))
			b.SetBytes(int64(len(value)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				session, _ := newStreamSession(stream, 64<<10)
				session.UseBigClrChunks = true
				var err error
				if appendTo {
					dst, err = session.AppendClr(dst[:0])
				} else {
					_, err = session.GetClr()
				}
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
