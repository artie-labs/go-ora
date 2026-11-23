package go_ora

import (
	"testing"

	"github.com/sijms/go-ora/v2/network"
)

func TestLobReadDataAppendsToCallersBuffer(t *testing.T) {
	// Two parts of a LOB's data, each a short CLR value, as a read's msg 14 parts carry them.
	input := append([]byte{3}, "abc"...)
	input = append(input, 2, 'd', 'e')
	lob := &Lob{connection: &Connection{session: network.NewSessionWithInputBufferForDebug(input)}}
	lob.into, lob.reading = []byte("x"), true
	for i := 0; i < 2; i++ {
		if err := lob.readData(); err != nil {
			t.Fatal(err)
		}
	}
	if string(lob.into) != "xabcde" {
		t.Fatalf("got %q", lob.into)
	}
	if lob.data.Len() != 0 {
		t.Fatalf("the LOB's own buffer holds %d bytes", lob.data.Len())
	}
}
