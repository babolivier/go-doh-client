package doh

import (
	"encoding/base64"
	"testing"
)

// Test data
const queryEncodedB64 = "ARAAAQAAAAAAAAdicmVuZGFuCWFib2xpdmllcgNiemgAAAEAAQ"

func TestEncodeQuery(t *testing.T) {
	q := encodeQuery("brendan.abolivier.bzh", A, IN)

	// Don't check the randomly generated ID.
	q = q[2:]
	if base64.RawStdEncoding.EncodeToString(q) != queryEncodedB64 {
		t.Fail()
	}
}
