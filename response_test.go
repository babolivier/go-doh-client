package doh

import (
	"encoding/base64"
	"testing"
)

// Test data

// This message contains valid accepted headers along with three CNAME answers and one A answer.
const validResponse = "vCOBkAABAAQAAAABB2JyZW5kYW4JYWJvbGl2aWVyA2J6aAAAAQABwAwABQABAAAOEAAHBGJsb2fADMAzAAUAAQAADhAAGwRibG9nEGJyZW5kYW5hYm9saXZpZXIDY29tAMBGAAUAAQABUYAACQZhcmFnb2fAS8BtAAEAAQAABwgABDMmL78AACkFrAAAAAAAAA"
const validAnswersCount = 4
const validCNAMECount = 3
const validACount = 1

// This message contains the same payload as above, but with QR = 0, meaning it's a query, not a response.
const notResponse = "xRYBkAABAAQAAAABB2JyZW5kYW4JYWJvbGl2aWVyA2J6aAAAAQABwAwABQABAAAOEAAHBGJsb2fADMAzAAUAAQAADhAAGwRibG9nEGJyZW5kYW5hYm9saXZpZXIDY29tAMBGAAUAAQAABI0ACQZhcmFnb2fAS8BtAAEAAQAABwgABDMmL78AACkFrAAAAAAAAA"

// This message contains the same payload as above, but with OPCODE = 1, meaning it's not a standard query (0), which is the only value currently supported.
const notStandardQuery = "psCJkAABAAQAAAABB2JyZW5kYW4JYWJvbGl2aWVyA2J6aAAAAQABwAwABQABAAAOEAAHBGJsb2fADMAzAAUAAQAADhAAGwRibG9nEGJyZW5kYW5hYm9saXZpZXIDY29tAMBGAAUAAQAAAPsACQZhcmFnb2fAS8BtAAEAAQAABwgABDMmL78AACkFrAAAAAAAAA"

// This message contains the same payload as above, but with TR = 1, meaning it's truncated, which isn' currently supported.
const truncated = "Iw2DkAABAAQAAAABB2JyZW5kYW4JYWJvbGl2aWVyA2J6aAAAAQABwAwABQABAAAOEAAHBGJsb2fADMAzAAUAAQAADhAAGwRibG9nEGJyZW5kYW5hYm9saXZpZXIDY29tAMBGAAUAAQAAAFYACQZhcmFnb2fAS8BtAAEAAQAABwgABDMmL78AACkFrAAAAAAAAA"

// This message contains the same payload as above, but with RCODE = 1 (format error).
const formatError = "EnuBkQABAAQAAAABB2JyZW5kYW4JYWJvbGl2aWVyA2J6aAAAAQABwAwABQABAAAIKwAHBGJsb2fADMAzAAUAAQAACCsAGwRibG9nEGJyZW5kYW5hYm9saXZpZXIDY29tAMBGAAUAAQABUYAACQZhcmFnb2fAS8BtAAEAAQAABwgABDMmL78AACkFrAAAAAAAAA"

// This message contains the same payload as above, but with RCODE = 2 (server failure).
const serverFailure = "GBqBkgABAAQAAAABB2JyZW5kYW4JYWJvbGl2aWVyA2J6aAAAAQABwAwABQABAAAOEAAHBGJsb2fADMAzAAUAAQAADhAAGwRibG9nEGJyZW5kYW5hYm9saXZpZXIDY29tAMBGAAUAAQABUYAACQZhcmFnb2fAS8BtAAEAAQAABwgABDMmL78AACkFrAAAAAAAAA"

// This message contains the same payload as above, but with RCODE = 3 (name error).
const nameError = "LkaBkwABAAQAAAABB2JyZW5kYW4JYWJvbGl2aWVyA2J6aAAAAQABwAwABQABAAAOEAAHBGJsb2fADMAzAAUAAQAADhAAGwRibG9nEGJyZW5kYW5hYm9saXZpZXIDY29tAMBGAAUAAQABUYAACQZhcmFnb2fAS8BtAAEAAQAABwgABDMmL78AACkFrAAAAAAAAA"

// This message contains the same payload as above, but with RCODE = 4 (not implemented).
const notImplemented = "79SBlAABAAQAAAABB2JyZW5kYW4JYWJvbGl2aWVyA2J6aAAAAQABwAwABQABAAAOEAAHBGJsb2fADMAzAAUAAQAADhAAGwRibG9nEGJyZW5kYW5hYm9saXZpZXIDY29tAMBGAAUAAQABUYAACQZhcmFnb2fAS8BtAAEAAQAABwgABDMmL78AACkFrAAAAAAAAA"

// This message contains the same payload as above, but with RCODE = 5 (refused).
const refused = "nHWBlQABAAQAAAABB2JyZW5kYW4JYWJvbGl2aWVyA2J6aAAAAQABwAwABQABAAAOEAAHBGJsb2fADMAzAAUAAQAADhAAGwRibG9nEGJyZW5kYW5hYm9saXZpZXIDY29tAMBGAAUAAQABUYAACQZhcmFnb2fAS8BtAAEAAQAABwgABDMmL78AACkFrAAAAAAAAA"

// This message contains an empty payload.
const empty = ""

// This messages contains a message header, but no corresponding resource records.
const noRecords = "V8yBkAABAAEAAAAA"

func TestValidHeaders(t *testing.T) {
	res, err := base64.RawStdEncoding.DecodeString(validResponse)
	if err != nil {
		t.FailNow()
	}

	// parseResponse only returns an error if something in the header isn't right.
	if _, err = parseResponse(res); err != nil {
		t.Fail()
	}
}

func TestValidAnswers(t *testing.T) {
	res, err := base64.RawStdEncoding.DecodeString(validResponse)
	if err != nil {
		t.FailNow()
	}

	// errors are checked in the test above, so we ignore them for now
	answers, _ := parseResponse(res)

	if len(answers) != validAnswersCount {
		t.Fail()
	}

	if c := countAnswers(CNAME, answers); c != validCNAMECount {
		t.Fail()
	}

	if c := countAnswers(A, answers); c != validACount {
		t.Fail()
	}
}

func countAnswers(t DNSType, answers []answer) (c int) {
	for _, a := range answers {
		if a.t == t {
			c++
		}
	}
	return
}

// Testing error handling.

func TestNotAResponse(t *testing.T) {
	res, err := base64.RawStdEncoding.DecodeString(notResponse)
	if err != nil {
		t.FailNow()
	}

	if _, err = parseResponse(res); err == nil || err != ErrNotAResponse {
		t.Fail()
	}
}

func TestNotStandardQuery(t *testing.T) {
	res, err := base64.RawStdEncoding.DecodeString(notStandardQuery)
	if err != nil {
		t.FailNow()
	}

	if _, err = parseResponse(res); err == nil || err != ErrNotStandardQuery {
		t.Fail()
	}
}

func TestTruncated(t *testing.T) {
	res, err := base64.RawStdEncoding.DecodeString(truncated)
	if err != nil {
		t.FailNow()
	}

	if _, err = parseResponse(res); err == nil || err != ErrTruncated {
		t.Fail()
	}
}

func TestFormatError(t *testing.T) {
	res, err := base64.RawStdEncoding.DecodeString(formatError)
	if err != nil {
		t.FailNow()
	}

	if _, err = parseResponse(res); err == nil || err != ErrFormatError {
		t.Fail()
	}
}

func TestServerFailure(t *testing.T) {
	res, err := base64.RawStdEncoding.DecodeString(serverFailure)
	if err != nil {
		t.FailNow()
	}

	if _, err = parseResponse(res); err == nil || err != ErrServerFailure {
		t.Fail()
	}
}

func TestNameError(t *testing.T) {
	res, err := base64.RawStdEncoding.DecodeString(nameError)
	if err != nil {
		t.FailNow()
	}

	if _, err = parseResponse(res); err == nil || err != ErrNameError {
		t.Fail()
	}
}

func TestNotImplemented(t *testing.T) {
	res, err := base64.RawStdEncoding.DecodeString(notImplemented)
	if err != nil {
		t.FailNow()
	}

	if _, err = parseResponse(res); err == nil || err != ErrNotImplemented {
		t.Fail()
	}
}

func TestRefused(t *testing.T) {
	res, err := base64.RawStdEncoding.DecodeString(refused)
	if err != nil {
		t.FailNow()
	}

	if _, err = parseResponse(res); err == nil || err != ErrRefused {
		t.Fail()
	}
}

func TestEmpty(t *testing.T) {
	if _, err := parseResponse([]byte(empty)); err == nil || err != ErrCorrupted {
		t.Fail()
	}
}

func TestCorrupted(t *testing.T) {
	res, err := base64.RawStdEncoding.DecodeString(noRecords)
	if err != nil {
		t.FailNow()
	}
	if _, err := parseResponse(res); err == nil || err != ErrCorrupted {
		t.Fail()
	}
}
