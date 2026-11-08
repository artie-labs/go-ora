package go_ora

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sijms/go-ora/v2/configurations"
	"github.com/sijms/go-ora/v2/converters"
	"github.com/sijms/go-ora/v2/network"
	"github.com/sijms/go-ora/v2/trace"
)

// fetchReplay is a query's responses as Oracle sent them, with the session settings that decoding them depends on.
// testdata/fetch_replay.gob.gz holds one, recorded from Oracle Free 23ai by TestRecordFetchReplay, for:
//
//	SELECT ID, N, S, S2, D, TS, R, C, NC FROM GOORA_T ORDER BY ID
//
// with PREFETCH_ROWS 50 over 300 rows of NUMBER, NUMBER(20,5), VARCHAR2(4000) (up to 4000 bytes of 2-byte
// characters, sent in chunks), VARCHAR2(100) repeated across rows (sent once, then marked in a bit vector), DATE,
// TIMESTAMP(9), RAW(200), CLOB (up to 100,000 characters, fetched inline) and NVARCHAR2, each column NULL in some
// rows.
type fetchReplay struct {
	// Responses holds each response's data packet payloads, concatenated: the execute's, then each fetch's.
	Responses       [][]byte
	TTCVersion      uint8
	UseBigClrChunks bool
	ClrChunkSize    int
	TimeZone        []byte
	ServerCharset   int
	ServerNCharset  int
}

const fetchReplayFile = "testdata/fetch_replay.gob.gz"

// recordConn records the bytes the server sends for each request, from when it's armed.
type recordConn struct {
	net.Conn
	mu        sync.Mutex
	armed     bool
	lastRead  bool
	responses [][]byte
}

func (c *recordConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	if c.armed && c.lastRead {
		c.responses = append(c.responses, nil)
	}
	c.lastRead = false
	c.mu.Unlock()
	return c.Conn.Write(b)
}

func (c *recordConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.mu.Lock()
	c.lastRead = true
	if c.armed && len(c.responses) > 0 && n > 0 {
		last := len(c.responses) - 1
		c.responses[last] = append(c.responses[last], b[:n]...)
	}
	c.mu.Unlock()
	return n, err
}

type recordDialer struct{ conn *recordConn }

func (d *recordDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var nd net.Dialer
	conn, err := nd.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	d.conn = &recordConn{Conn: conn}
	return d.conn, nil
}

// dataPayloads strips the TNS framing from a response: each packet's 8-byte header and a data packet's 2 bytes of
// flags.
func dataPayloads(t *testing.T, stream []byte) []byte {
	var out []byte
	for len(stream) > 0 {
		size := int(binary.BigEndian.Uint32(stream))
		if stream[4] != 6 {
			t.Fatalf("packet type %d in a response", stream[4])
		}
		out = append(out, stream[10:size]...)
		stream = stream[size:]
	}
	return out
}

// TestRecordFetchReplay writes testdata/fetch_replay.gob.gz. Run it against a database holding GOORA_T:
//
//	GOORA_RECORD_DSN=oracle://user:password@host:port/service go test -run TestRecordFetchReplay .
func TestRecordFetchReplay(t *testing.T) {
	dsn := os.Getenv("GOORA_RECORD_DSN")
	if dsn == "" {
		t.Skip("GOORA_RECORD_DSN is not set")
	}
	connector, err := NewDriver().OpenConnector(dsn + "?PREFETCH_ROWS=50")
	if err != nil {
		t.Fatal(err)
	}
	dialer := &recordDialer{}
	connector.(*OracleConnector).Dialer(dialer)
	db := sql.OpenDB(connector)
	defer db.Close()
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var replay fetchReplay
	err = conn.Raw(func(dc any) error {
		c := dc.(*Connection)
		replay.TTCVersion = c.session.TTCVersion
		replay.UseBigClrChunks = c.session.UseBigClrChunks
		replay.ClrChunkSize = c.session.ClrChunkSize
		replay.TimeZone = c.session.TimeZone
		replay.ServerCharset = c.tcpNego.ServerCharset
		replay.ServerNCharset = c.tcpNego.ServernCharset
		dialer.conn.mu.Lock()
		dialer.conn.armed, dialer.conn.lastRead = true, true
		dialer.conn.mu.Unlock()
		rows, err := c.QueryContext(ctx, "SELECT ID, N, S, S2, D, TS, R, C, NC FROM GOORA_T ORDER BY ID", nil)
		if err != nil {
			return err
		}
		dest := make([]driver.Value, len(rows.Columns()))
		count := 0
		for {
			if err := rows.Next(dest); err == io.EOF {
				break
			} else if err != nil {
				return err
			}
			count++
		}
		dialer.conn.mu.Lock()
		dialer.conn.armed = false
		dialer.conn.mu.Unlock()
		t.Logf("recorded %d rows in %d responses", count, len(dialer.conn.responses))
		return rows.Close()
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, response := range dialer.conn.responses {
		replay.Responses = append(replay.Responses, dataPayloads(t, response))
	}
	f, err := os.Create(fetchReplayFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := gzip.NewWriter(f)
	if err := gob.NewEncoder(zw).Encode(replay); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}

func loadFetchReplay(t testing.TB) fetchReplay {
	f, err := os.Open(fetchReplayFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var replay fetchReplay
	if err := gob.NewDecoder(zr).Decode(&replay); err != nil {
		t.Fatal(err)
	}
	return replay
}

// decodeFetchReplay decodes the responses as a query does, each response from its own session buffer, and returns
// the rows.
func decodeFetchReplay(t testing.TB, replay fetchReplay) []Row {
	c := new(Connection)
	c.connOption = &configurations.ConnectionConfig{}
	c.connOption.Lob = configurations.INLINE
	c.sStrConv = converters.NewStringConverter(replay.ServerCharset)
	c.nStrConv = converters.NewStringConverter(replay.ServerNCharset)
	c.tcpNego = &TCPNego{ServerCharset: replay.ServerCharset, ServernCharset: replay.ServerNCharset}
	c.tracer = trace.NilTracer()
	c.dbServerTimeZone, c.dbTimeZone = time.UTC, time.UTC
	stmt := new(Stmt)
	stmt.connection = c
	stmt.stmtType = SELECT
	stmt.scnForSnapshot = make([]int, 2)
	stmt._hasMoreRows = true
	// One result set for the execute, the define and the fetches, as a query uses.
	resultSet := new(ResultSet)
	var rows []Row
	for i, response := range replay.Responses {
		c.session = network.NewSessionWithInputBufferForDebug(response)
		c.session.TTCVersion = replay.TTCVersion
		c.session.UseBigClrChunks = replay.UseBigClrChunks
		c.session.ClrChunkSize = replay.ClrChunkSize
		c.session.TimeZone = replay.TimeZone
		c.session.StrConv = c.sStrConv
		resultSet.rows = nil
		if err := stmt.read(resultSet); err != nil {
			t.Fatalf("response %d: %v", i, err)
		}
		if err := stmt.decodePrim(resultSet); err != nil {
			t.Fatalf("response %d: %v", i, err)
		}
		rows = append(rows, resultSet.rows...)
		if !stmt._hasMoreRows {
			break
		}
		// After the execute's describe, a query with LOB columns sends a define that fetches them inline, as LONG
		// columns (see Stmt._query).
		if i == 0 && (stmt._hasBLOB || stmt._hasLONG) {
			if err := stmt.writeDefine(); err != nil {
				t.Fatal(err)
			}
		}
	}
	return rows
}

// renderRow writes a row's values with their types, hashing values over 64 characters.
func renderRow(row Row) string {
	parts := make([]string, len(row))
	for i, value := range row {
		var s string
		switch v := value.(type) {
		case nil:
			s = "nil"
		case []byte:
			s = "bytes:" + hex.EncodeToString(v)
		case time.Time:
			s = "time:" + v.Format(time.RFC3339Nano) + " " + v.Location().String()
		default:
			s = fmt.Sprintf("%T:%v", v, v)
		}
		if len(s) > 64 {
			sum := sha256.Sum256([]byte(s))
			s = fmt.Sprintf("%s...(%d chars, sha256 %x)", s[:24], len(s), sum[:8])
		}
		parts[i] = s
	}
	return strings.Join(parts, " | ")
}

const fetchReplayGolden = "testdata/fetch_replay.golden"

// TestFetchReplay decodes recorded responses and compares every value with what go-ora v2.9.0 decoded from them,
// which GOORA_UPDATE_GOLDEN=1 writes.
func TestFetchReplay(t *testing.T) {
	replay := loadFetchReplay(t)
	rows := decodeFetchReplay(t, replay)
	var b strings.Builder
	for _, row := range rows {
		b.WriteString(renderRow(row))
		b.WriteByte('\n')
	}
	if os.Getenv("GOORA_UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(fetchReplayGolden, []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(fetchReplayGolden)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 300 {
		t.Fatalf("decoded %d rows, want 300", len(rows))
	}
	got := bufio.NewScanner(strings.NewReader(b.String()))
	expected := bufio.NewScanner(bytes.NewReader(want))
	for line := 1; expected.Scan(); line++ {
		if !got.Scan() {
			t.Fatalf("row %d missing", line)
		}
		if got.Text() != expected.Text() {
			t.Fatalf("row %d:\n got %s\nwant %s", line, got.Text(), expected.Text())
		}
	}
	if got.Scan() {
		t.Fatalf("extra row: %s", got.Text())
	}
}

// BenchmarkFetchReplay times decoding the recorded responses.
func BenchmarkFetchReplay(b *testing.B) {
	replay := loadFetchReplay(b)
	var size int
	for _, r := range replay.Responses {
		size += len(r)
	}
	b.SetBytes(int64(size))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = decodeFetchReplay(b, replay)
	}
}
