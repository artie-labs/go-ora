package network

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sijms/go-ora/v2/configurations"
	"github.com/sijms/go-ora/v2/trace"
)

// streamConn serves a fixed byte stream to reads, in pieces of at most step bytes, as a socket does.
type streamConn struct {
	net.Conn
	data []byte
	step int
}

func (c *streamConn) Read(b []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := minInt(minInt(len(b), len(c.data)), c.step)
	copy(b, c.data[:n])
	c.data = c.data[n:]
	return n, nil
}

func (c *streamConn) SetReadDeadline(time.Time) error { return nil }

// dataPackets splits payload into TNS data packets of at most size payload bytes each, framed as after the
// handshake: a 4-byte length, the type, a flag, a 2-byte checksum and 2 bytes of data flags.
func dataPackets(payload []byte, size int) []byte {
	var out []byte
	for len(payload) > 0 {
		n := minInt(size, len(payload))
		header := make([]byte, 10)
		binary.BigEndian.PutUint32(header, uint32(10+n))
		header[4] = byte(DATA)
		out = append(out, header...)
		out = append(out, payload[:n]...)
		payload = payload[n:]
	}
	return out
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func newStreamSession(stream []byte, step int) *Session {
	config := &configurations.ConnectionConfig{}
	session := NewSession(config, trace.NilTracer())
	session.Context.handshakeComplete = true
	conn := &streamConn{data: stream, step: step}
	session.conn = conn
	session.reader = bufio.NewReaderSize(conn, read_buffer_size)
	return session
}

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i/251)
	}
	return b
}

func TestSessionReadAcrossPackets(t *testing.T) {
	{
		// Reads of every size cross packet and block boundaries, and each returned slice keeps its bytes after the
		// reads that follow it, which callers holding LOB locators and object attributes rely on.
		payload := pattern(400_000)
		session := newStreamSession(dataPackets(payload, 997), 1500)
		type held struct {
			offset int
			bytes  []byte
		}
		var kept []held
		offset := 0
		for size := 1; offset < len(payload); size = size%3000 + 1 {
			size = minInt(size, len(payload)-offset)
			got, err := session.read(size)
			if err != nil {
				t.Fatalf("read %d at %d: %v", size, offset, err)
			}
			if !bytes.Equal(got, payload[offset:offset+size]) {
				t.Fatalf("read %d at %d: wrong bytes", size, offset)
			}
			kept = append(kept, held{offset, got})
			offset += size
		}
		for _, h := range kept {
			if !bytes.Equal(h.bytes, payload[h.offset:h.offset+len(h.bytes)]) {
				t.Fatalf("bytes read at %d changed after later reads", h.offset)
			}
		}
		// The buffer holds about two packets, not the whole response.
		if cap(session.inBuffer) > 4*minDataBlock {
			t.Fatalf("inBuffer capacity %d for a %d-byte response", cap(session.inBuffer), len(payload))
		}
		if _, err := session.read(1); err == nil {
			t.Fatal("read past the end of the stream succeeded")
		}
	}
	{
		// Packets larger than a block.
		payload := pattern(3 * minDataBlock)
		session := newStreamSession(dataPackets(payload, 2*minDataBlock+5), 1<<20)
		got, err := session.read(10)
		if err != nil || !bytes.Equal(got, payload[:10]) {
			t.Fatalf("first read: %v", err)
		}
		got, err = session.read(len(payload) - 10)
		if err != nil || !bytes.Equal(got, payload[10:]) {
			t.Fatalf("second read: %v", err)
		}
	}
}

func TestSessionReadCapacity(t *testing.T) {
	// Appending to a returned slice copies it instead of overwriting the bytes read next.
	payload := pattern(64)
	session := newStreamSession(dataPackets(payload, 64), 64)
	first, err := session.read(8)
	if err != nil {
		t.Fatal(err)
	}
	_ = append(first, 0xAA, 0xBB)
	rest, err := session.read(56)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rest, payload[8:]) {
		t.Fatal("append to a returned slice overwrote the next bytes")
	}
}

func TestSessionPeek(t *testing.T) {
	payload := pattern(3 * minDataBlock)
	session := newStreamSession(dataPackets(payload, 1000), 4096)
	offset := 0
	for offset+700 <= len(payload) {
		// The peeked bytes straddle packets, so the peek may move the unread bytes to a new block.
		peeked, err := session.Peek(700)
		if err != nil {
			t.Fatalf("peek at %d: %v", offset, err)
		}
		if !bytes.Equal(peeked, payload[offset:offset+700]) {
			t.Fatalf("peek at %d: wrong bytes", offset)
		}
		got, err := session.read(333)
		if err != nil {
			t.Fatalf("read at %d: %v", offset, err)
		}
		if !bytes.Equal(got, payload[offset:offset+333]) {
			t.Fatalf("read after peek at %d: wrong bytes", offset)
		}
		offset += 333
	}
}

func TestSessionGetNullTermString(t *testing.T) {
	{
		// The string ends in the next packet, and the read continues right after its terminator.
		payload := append(bytes.Repeat([]byte{'x'}, 30), 0)
		payload = append(payload, []byte("after the string, more")...)
		session := newStreamSession(dataPackets(payload, 20), 20)
		s, err := session.GetNullTermString(50)
		if err != nil {
			t.Fatal(err)
		}
		if s != string(bytes.Repeat([]byte{'x'}, 30)) {
			t.Fatalf("got %q", s)
		}
		rest, err := session.read(5)
		if err != nil || string(rest) != "after" {
			t.Fatalf("read after the string: %q, %v", rest, err)
		}
	}
	{
		// The string is in a packet too large for the first block's spare capacity, so the read moves the unread
		// bytes to a new block.
		first := pattern(40_000)
		second := append([]byte("abc\x00tail"), pattern(50_000)...)
		stream := append(dataPackets(first, len(first)), dataPackets(second, len(second))...)
		session := newStreamSession(stream, 1<<20)
		if _, err := session.read(len(first) - 2); err != nil {
			t.Fatal(err)
		}
		if _, err := session.read(2); err != nil {
			t.Fatal(err)
		}
		s, err := session.GetNullTermString(20)
		if err != nil || s != "abc" {
			t.Fatalf("got %q, %v", s, err)
		}
		rest, err := session.read(4)
		if err != nil || string(rest) != "tail" {
			t.Fatalf("read after the string: %q, %v", rest, err)
		}
	}
}

func TestSessionAppendData(t *testing.T) {
	{
		// Spare capacity takes the payload without moving anything.
		session := &Session{inBuffer: make([]byte, 4, 16), index: 2}
		before := &session.inBuffer[0]
		session.appendData([]byte{9, 9})
		if &session.inBuffer[0] != before || session.index != 2 || len(session.inBuffer) != 6 {
			t.Fatal("append into spare capacity moved the buffer")
		}
	}
	{
		// A new block starts at the first unread byte, the old block is untouched, and breakIndex moves with it.
		old := []byte{1, 2, 3, 4, 5, 6}
		session := &Session{inBuffer: old[:6:6], index: 4, breakIndex: 6}
		session.appendData([]byte{7, 8})
		if !bytes.Equal(session.inBuffer, []byte{5, 6, 7, 8}) || session.index != 0 || session.breakIndex != 2 {
			t.Fatalf("got %v index %d breakIndex %d", session.inBuffer, session.index, session.breakIndex)
		}
		if !bytes.Equal(old, []byte{1, 2, 3, 4, 5, 6}) {
			t.Fatal("the old block changed")
		}
		if cap(session.inBuffer) < minDataBlock {
			t.Fatalf("new block capacity %d", cap(session.inBuffer))
		}
	}
}
