package doh

import (
	"encoding/base64"
	"fmt"
	"reflect"
	"testing"
)

// Test data
const rdataA = "MyYvvw"
const expectedA = "51.38.47.191"
const rdataAAAA = "IAFB0AMCEQAAAAAAAArY8Q"
const expectedAAAA = "2001:41d0:302:1100:0:0:a:d8f1"
const rdataCNAME = "BWVycm9sEGJyZW5kYW5hYm9saXZpZXIDY29tAA"
const expectedCNAME = "errol.brendanabolivier.com"
const rdataMX = "AAEDbXgzA292aANuZXQA"
const expectedMXHost = "mx3.ovh.net"
const expectedMXPref = 1
const rdataSRV = "AAoAACEABGNoYXQJYWJvbGl2aWVyA2J6aAA"
const expectedSRVPriority = 10
const expectedSRVWeight = 0
const expectedSRVPort = 8448
const expectedSRVTarget = "chat.abolivier.bzh"
const rdataNS = "BW5zMjAwB2FueWNhc3QCbWUA"
const expectedNSHost = "ns200.anycast.me"
const rdataTXT = "HzR8aHR0cHM6Ly9icmVuZGFuLmFib2xpdmllci5iemg"
const expectedTXT = "4|https://brendan.abolivier.bzh"
const rdataSOA = "BmRuczIwMAdhbnljYXN0Am1lAAR0ZWNoA292aANuZXQAeFfPoAABUYAAAA4QADbugAAAASw"
const expectedSOAPrimaryNS = "dns200.anycast.me"
const expectedSOARespMailbox = "tech.ovh.net"
const expectedSOASerial = 2019020704
const expectedSOARefresh = 86400
const expectedSOARetry = 3600
const expectedSOAExpire = 3600000
const expectedSOAMinimum = 300
const rdataPTR = "BmFyYWdvZxBicmVuZGFuYWJvbGl2aWVyA2NvbQA"
const expectedPTR = "aragog.brendanabolivier.com"
const name = "CWFib2xpdmllcgNiemgA"
const expectedName = "abolivier.bzh"
const expectedOffset = 15

func TestParseFlow(t *testing.T) {
	testParseType(t, rdataA, "A", A)
	testParseType(t, rdataAAAA, "AAAA", AAAA)
	testParseType(t, rdataCNAME, "CNAME", CNAME)
	testParseType(t, rdataMX, "MX", MX)
	testParseType(t, rdataSRV, "SRV", SRV)
	testParseType(t, rdataNS, "NS", NS)
	testParseType(t, rdataTXT, "TXT", TXT)
	testParseType(t, rdataSOA, "SOA", SOA)
	testParseType(t, rdataPTR, "PTR", PTR)
}

func testParseType(t *testing.T, b64, expectedType string, recordType DNSType) {
	rdata, err := base64.RawStdEncoding.DecodeString(b64)
	if err != nil {
		t.FailNow()
	}

	p := new(parser)
	parsed := p.parse(recordType, ANYCLASS, rdata)

	expected := fmt.Sprintf("*doh.%sRecord", expectedType)
	if reflect.TypeOf(parsed).String() != expected {
		t.Fail()
	}
}

func TestParseA(t *testing.T) {
	rdata, err := base64.RawStdEncoding.DecodeString(rdataA)
	if err != nil {
		t.FailNow()
	}

	p := new(parser)
	rec := p.parseA(rdata)
	if rec.IP4 != expectedA {
		t.Fail()
	}
}

func TestParseAAAA(t *testing.T) {
	rdata, err := base64.RawStdEncoding.DecodeString(rdataAAAA)
	if err != nil {
		t.FailNow()
	}

	p := new(parser)
	rec := p.parseAAAA(rdata)
	if rec.IP6 != expectedAAAA {
		t.Fail()
	}
}

func TestParseCNAME(t *testing.T) {
	rdata, err := base64.RawStdEncoding.DecodeString(rdataCNAME)
	if err != nil {
		t.FailNow()
	}

	p := new(parser)
	rec := p.parseCNAME(rdata)
	if rec.CNAME != expectedCNAME {
		t.Fail()
	}
}

func TestParseMX(t *testing.T) {
	rdata, err := base64.RawStdEncoding.DecodeString(rdataMX)
	if err != nil {
		t.FailNow()
	}

	p := new(parser)
	rec := p.parseMX(rdata)

	if rec.Host != expectedMXHost {
		t.Fail()
	}

	if rec.Pref != expectedMXPref {
		t.Fail()
	}
}

func TestParseSRV(t *testing.T) {
	rdata, err := base64.RawStdEncoding.DecodeString(rdataSRV)
	if err != nil {
		t.FailNow()
	}

	p := new(parser)
	rec := p.parseSRV(rdata)
	if rec.Priority != expectedSRVPriority {
		t.Fail()
	}

	if rec.Weight != expectedSRVWeight {
		t.Fail()
	}

	if rec.Port != expectedSRVPort {
		t.Fail()
	}

	if rec.Target != expectedSRVTarget {
		t.Fail()
	}
}

func TestParseNS(t *testing.T) {
	rdata, err := base64.RawStdEncoding.DecodeString(rdataNS)
	if err != nil {
		t.FailNow()
	}

	p := new(parser)
	rec := p.parseNS(rdata)
	if rec.Host != expectedNSHost {
		t.Fail()
	}
}

func TestParseTXT(t *testing.T) {
	rdata, err := base64.RawStdEncoding.DecodeString(rdataTXT)
	if err != nil {
		t.FailNow()
	}

	p := new(parser)
	rec := p.parseTXT(rdata)
	if rec.TXT != expectedTXT {
		t.Fail()
	}
}

func TestParseSOA(t *testing.T) {
	rdata, err := base64.RawStdEncoding.DecodeString(rdataSOA)
	if err != nil {
		t.FailNow()
	}

	p := new(parser)
	rec := p.parseSOA(rdata)

	if rec.PrimaryNS != expectedSOAPrimaryNS {
		t.Fail()
	}

	if rec.RespMailbox != expectedSOARespMailbox {
		t.Fail()
	}

	if rec.Serial != expectedSOASerial {
		t.Fail()
	}

	if rec.Refresh != expectedSOARefresh {
		t.Fail()
	}

	if rec.Retry != expectedSOARetry {
		t.Fail()
	}
}

func TestParsePTR(t *testing.T) {
	rdata, err := base64.RawStdEncoding.DecodeString(rdataPTR)
	if err != nil {
		t.FailNow()
	}

	p := new(parser)
	rec := p.parsePTR(rdata)
	if rec.PTR != expectedPTR {
		t.Fail()
	}
}

func TestParseName(t *testing.T) {
	b, err := base64.RawStdEncoding.DecodeString(name)
	if err != nil {
		t.FailNow()
	}

	p := new(parser)
	n, o := p.parseName(b)
	if n != expectedName || o != expectedOffset {
		t.Fail()
	}
}
