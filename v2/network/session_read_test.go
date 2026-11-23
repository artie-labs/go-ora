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
	{
		// A response's first packet, after ResetBuffer, gets a block of its own size.
		session := &Session{}
		session.appendData([]byte{1, 2, 3})
		if !bytes.Equal(session.inBuffer, []byte{1, 2, 3}) || cap(session.inBuffer) != 3 {
			t.Fatalf("first block %v, capacity %d", session.inBuffer, cap(session.inBuffer))
		}
	}
}

// clr encodes value as the server sends a column value: a length byte, or 0xFE and chunks of at most chunk bytes
// with 1-byte sizes (4-byte compressed sizes when big), ending with an empty chunk.
func clr(value []byte, chunk int, big bool) []byte {
	if len(value) < 0xFE && chunk == 0 {
		return append([]byte{byte(len(value))}, value...)
	}
	out := []byte{0xFE}
	size := func(n int) {
		if big {
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], uint32(n))
			trimmed := bytes.TrimLeft(b[:], "\x00")
			out = append(out, byte(len(trimmed)))
			out = append(out, trimmed...)
		} else {
			out = append(out, byte(n))
		}
	}
	for len(value) > 0 {
		n := minInt(chunk, len(value))
		size(n)
		out = append(out, value[:n]...)
		value = value[n:]
	}
	size(0)
	return out
}

func TestSessionGetClr(t *testing.T) {
	long := pattern(70_000)
	var stream []byte
	stream = append(stream, 0)    // NULL
	stream = append(stream, 0xFF) // NULL
	stream = append(stream, clr([]byte("abc"), 0, false)...)
	stream = append(stream, clr(long[:252], 0, false)...)
	stream = append(stream, clr(long[:4000], 64, false)...)
	stream = append(stream, clr(long, 32767, true)...)
	stream = append(stream, 0xFE, 0) // chunked with no chunks: NULL
	{
		for _, packet := range []int{7, 100, 8192, 1 << 20} {
			session := newStreamSession(dataPackets(stream, packet), packet)
			session.UseBigClrChunks = false
			want := [][]byte{nil, nil, []byte("abc"), long[:252], long[:4000]}
			for i, w := range want {
				got, err := session.GetClr()
				if err != nil {
					t.Fatalf("packet %d, value %d: %v", packet, i, err)
				}
				if !bytes.Equal(got, w) || (w == nil) != (got == nil) {
					t.Fatalf("packet %d, value %d: wrong bytes", packet, i)
				}
				if got != nil && cap(got) != len(got) {
					t.Fatalf("packet %d, value %d: capacity %d for %d bytes", packet, i, cap(got), len(got))
				}
			}
			session.UseBigClrChunks = true
			got, err := session.GetClr()
			if err != nil || !bytes.Equal(got, long) {
				t.Fatalf("packet %d, big chunks: %v", packet, err)
			}
			got, err = session.GetClr()
			if err != nil || got != nil {
				t.Fatalf("packet %d, empty chunked value: %v, %v", packet, got, err)
			}
		}
	}
	{
		// The value is a copy: reading on doesn't change it.
		session := newStreamSession(dataPackets(append(clr([]byte("value"), 0, false), pattern(200_000)...), 1000), 1000)
		got, err := session.GetClr()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := session.read(200_000); err != nil {
			t.Fatal(err)
		}
		if string(got) != "value" {
			t.Fatalf("got %q", got)
		}
	}
}

func TestSessionAppendClr(t *testing.T) {
	long := pattern(70_000)
	var stream []byte
	stream = append(stream, 0) // NULL
	stream = append(stream, clr([]byte("abc"), 0, false)...)
	stream = append(stream, clr(long[:4000], 64, false)...)
	stream = append(stream, 0xFE, 0) // chunked with no chunks: NULL
	stream = append(stream, clr(long, 32767, true)...)
	for _, packet := range []int{7, 100, 8192, 1 << 20} {
		// Every value is appended after what dst holds, across packets and blocks, and a NULL appends nothing.
		session := newStreamSession(dataPackets(stream, packet), packet)
		dst := []byte("prefix")
		var err error
		want := append([]byte("prefix"), "abc"...)
		want = append(want, long[:4000]...)
		for i := 0; i < 4; i++ {
			if dst, err = session.AppendClr(dst); err != nil {
				t.Fatalf("packet %d, value %d: %v", packet, i, err)
			}
		}
		if !bytes.Equal(dst, want) {
			t.Fatalf("packet %d: wrong bytes", packet)
		}
		session.UseBigClrChunks = true
		if dst, err = session.AppendClr(dst[:0]); err != nil || !bytes.Equal(dst, long) {
			t.Fatalf("packet %d, big chunks: %v", packet, err)
		}
	}
	{
		// A buffer large enough takes the value without allocating.
		input := clr(long, 32767, true)
		dst := make([]byte, 0, len(long))
		allocs := testing.AllocsPerRun(10, func() {
			session := NewSessionWithInputBufferForDebug(input)
			session.UseBigClrChunks = true
			var err error
			if dst, err = session.AppendClr(dst[:0]); err != nil || len(dst) != len(long) {
				t.Fatal(err)
			}
		})
		var session *Session
		baseline := testing.AllocsPerRun(10, func() { session = NewSessionWithInputBufferForDebug(input) })
		_ = session
		if allocs != baseline {
			t.Fatalf("AppendClr allocated %v times beyond creating its session", allocs-baseline)
		}
	}
}

// BenchmarkSessionReadLOB reads a 1 MiB value in 32 KiB chunks from 8 KiB packets, as a BFILE read returns it.
func BenchmarkSessionReadLOB(b *testing.B) {
	value := pattern(1 << 20)
	stream := dataPackets(clr(value, 32767, true), 8192)
	b.Run("GetClr", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(value)))
		for i := 0; i < b.N; i++ {
			session := newStreamSession(stream, len(stream))
			session.UseBigClrChunks = true
			if got, err := session.GetClr(); err != nil || len(got) != len(value) {
				b.Fatal(err)
			}
		}
	})
	b.Run("AppendClr", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(value)))
		dst := make([]byte, 0, len(value))
		for i := 0; i < b.N; i++ {
			session := newStreamSession(stream, len(stream))
			session.UseBigClrChunks = true
			var err error
			if dst, err = session.AppendClr(dst[:0]); err != nil || len(dst) != len(value) {
				b.Fatal(err)
			}
		}
	})
}
