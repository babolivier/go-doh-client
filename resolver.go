// Package doh implements client operations for DoH (DNS over HTTPS) lookups.
package doh

import (
	"context"
	"net/http"
)

// Resolver handles lookups.
type Resolver struct {
	// The host to send DoH requests to.
	Host string
	// The DNS class to lookup with, must be one of IN, CS, CH, HS or ANYCLASS.
	// As a hint, the most used class nowadays is IN (Internet).
	Class DNSClass
	// HttpClient is a http.Client used to connect to DoH server
	HTTPClient *http.Client
}

// lookup encodes a DNS query, sends it over HTTPS then parses the response.
// Returns an error if something went wrong at the network level, or when
// parsing the response headers.
func (r *Resolver) lookup(ctx context.Context, fqdn string, t DNSType, c DNSClass) ([]answer, error) {
	q, err := encodeQuery(fqdn, t, c)
	if err != nil {
		return nil, err
	}
	res, err := r.exchangeHTTPS(ctx, q)
	if err != nil {
		return nil, err
	}
	return parseResponse(res)
}

// LookupA performs a DoH lookup on A records for the given FQDN.
// Return records and TTLs such that ttls[0] is the TTL for recs[0], and so on.
// Returns an error if something went wrong at the network level, or when
// parsing the response headers, or if the resolver's class isn't IN.
func (r *Resolver) LookupA(fqdn string) (recs []*ARecord, ttls []uint32, err error) {
	return r.LookupACtx(context.Background(), fqdn)
}

// LookupACtx performs a DoH lookup on A records for the given FQDN.
// Return records and TTLs such that ttls[0] is the TTL for recs[0], and so on.
// Returns an error if something went wrong at the network level, or when
// parsing the response headers, or if the resolver's class isn't IN.
// In addition to LookupA it supports timeouts, cancellation and context propagation.
func (r *Resolver) LookupACtx(ctx context.Context, fqdn string) (recs []*ARecord, ttls []uint32, err error) {
	if r.Class != IN && r.Class != ANYCLASS {
		err = ErrNotIN
		return
	}

	answers, err := r.lookup(ctx, fqdn, A, IN)
	if err != nil {
		return
	}

	recs = make([]*ARecord, 0)
	ttls = make([]uint32, 0)

	for _, a := range answers {
		if a.t == A {
			recs = append(recs, a.parsed.(*ARecord))
			ttls = append(ttls, a.ttl)
		}
	}

	return
}

// LookupAAAACtx performs a DoH lookup on AAAA records for the given FQDN.
// Return records and TTLs such that ttls[0] is the TTL for recs[0], and so on.
// Returns an error if something went wrong at the network level, or when
// parsing the response headers, or if the resolver's class isn't IN.
// In addition to LookupAAAA it supports timeouts, cancellation and context propagation.
func (r *Resolver) LookupAAAACtx(ctx context.Context, fqdn string) (recs []*AAAARecord, ttls []uint32, err error) {
	if r.Class != IN && r.Class != ANYCLASS {
		err = ErrNotIN
		return
	}

	answers, err := r.lookup(ctx, fqdn, AAAA, IN)
	if err != nil {
		return
	}

	recs = make([]*AAAARecord, 0)
	ttls = make([]uint32, 0)

	for _, a := range answers {
		if a.t == AAAA {
			recs = append(recs, a.parsed.(*AAAARecord))
			ttls = append(ttls, a.ttl)
		}
	}

	return
}

// LookupAAAA performs a DoH lookup on AAAA records for the given FQDN.
// Return records and TTLs such that ttls[0] is the TTL for recs[0], and so on.
// Returns an error if something went wrong at the network level, or when
// parsing the response headers, or if the resolver's class isn't IN.
func (r *Resolver) LookupAAAA(fqdn string) (recs []*AAAARecord, ttls []uint32, err error) {
	return r.LookupAAAACtx(context.Background(), fqdn)
}

// LookupCNAMECtx performs a DoH lookup on CNAME records for the given FQDN.
// Return records and TTLs such that ttls[0] is the TTL for recs[0], and so on.
// Returns an error if something went wrong at the network level, or when
// parsing the response headers.
// In addition to LookupCNAME it supports timeouts, cancellation and context propagation.
func (r *Resolver) LookupCNAMECtx(ctx context.Context, fqdn string) (recs []*CNAMERecord, ttls []uint32, err error) {
	answers, err := r.lookup(ctx, fqdn, CNAME, IN)
	if err != nil {
		return
	}

	recs = make([]*CNAMERecord, 0)
	ttls = make([]uint32, 0)

	for _, a := range answers {
		if a.t == CNAME {
			recs = append(recs, a.parsed.(*CNAMERecord))
			ttls = append(ttls, a.ttl)
		}
	}

	return
}

// LookupCNAME performs a DoH lookup on CNAME records for the given FQDN.
// Return records and TTLs such that ttls[0] is the TTL for recs[0], and so on.
// Returns an error if something went wrong at the network level, or when
// parsing the response headers.
func (r *Resolver) LookupCNAME(fqdn string) (recs []*CNAMERecord, ttls []uint32, err error) {
	return r.LookupCNAMECtx(context.Background(), fqdn)
}

// LookupMXCtx performs a DoH lookup on CNAME records for the given FQDN.
// Return records and TTLs such that ttls[0] is the TTL for recs[0], and so on.
// Returns an error if something went wrong at the network level, or when
// parsing the response headers.
// In addition to LookupMX it supports timeouts, cancellation and context propagation.
func (r *Resolver) LookupMXCtx(ctx context.Context, fqdn string) (recs []*MXRecord, ttls []uint32, err error) {
	answers, err := r.lookup(ctx, fqdn, MX, IN)
	if err != nil {
		return
	}

	recs = make([]*MXRecord, 0)
	ttls = make([]uint32, 0)

	for _, a := range answers {
		if a.t == MX {
			recs = append(recs, a.parsed.(*MXRecord))
			ttls = append(ttls, a.ttl)
		}
	}

	return
}

// LookupMX performs a DoH lookup on CNAME records for the given FQDN.
// Return records and TTLs such that ttls[0] is the TTL for recs[0], and so on.
// Returns an error if something went wrong at the network level, or when
// parsing the response headers.
func (r *Resolver) LookupMX(fqdn string) (recs []*MXRecord, ttls []uint32, err error) {
	return r.LookupMXCtx(context.Background(), fqdn)
}

// LookupNSCtx performs a DoH lookup on CNAME records for the given FQDN.
// Return records and TTLs such that ttls[0] is the TTL for recs[0], and so on.
// Returns an error if something went wrong at the network level, or when
// parsing the response headers.
// In addition to LookupNS it supports timeouts, cancellation and context propagation.
func (r *Resolver) LookupNSCtx(ctx context.Context, fqdn string) (recs []*NSRecord, ttls []uint32, err error) {
	answers, err := r.lookup(ctx, fqdn, NS, IN)
	if err != nil {
		return
	}

	recs = make([]*NSRecord, 0)
	ttls = make([]uint32, 0)

	for _, a := range answers {
		if a.t == NS {
			recs = append(recs, a.parsed.(*NSRecord))
			ttls = append(ttls, a.ttl)
		}
	}

	return
}

// LookupNS performs a DoH lookup on CNAME records for the given FQDN.
// Return records and TTLs such that ttls[0] is the TTL for recs[0], and so on.
// Returns an error if something went wrong at the network level, or when
// parsing the response headers.
func (r *Resolver) LookupNS(fqdn string) (recs []*NSRecord, ttls []uint32, err error) {
	return r.LookupNSCtx(context.Background(), fqdn)
}

// LookupTXTCtx performs a DoH lookup on TXT records for the given FQDN.
// Return records and TTLs such that ttls[0] is the TTL for recs[0], and so on.
// Returns an error if something went wrong at the network level, or when
// parsing the response headers.
// In addition to LookupTXT it supports timeouts, cancellation and context propagation.
func (r *Resolver) LookupTXTCtx(ctx context.Context, fqdn string) (recs []*TXTRecord, ttls []uint32, err error) {
	answers, err := r.lookup(ctx, fqdn, TXT, IN)
	if err != nil {
		return
	}

	recs = make([]*TXTRecord, 0)
	ttls = make([]uint32, 0)

	for _, a := range answers {
		if a.t == TXT {
			recs = append(recs, a.parsed.(*TXTRecord))
			ttls = append(ttls, a.ttl)
		}
	}

	return
}

// LookupTXT performs a DoH lookup on TXT records for the given FQDN.
// Return records and TTLs such that ttls[0] is the TTL for recs[0], and so on.
// Returns an error if something went wrong at the network level, or when
// parsing the response headers.
func (r *Resolver) LookupTXT(fqdn string) (recs []*TXTRecord, ttls []uint32, err error) {
	return r.LookupTXTCtx(context.Background(), fqdn)
}

// LookupSRVCtx performs a DoH lookup on SRV records for the given FQDN.
// Return records and TTLs such that ttls[0] is the TTL for recs[0], and so on.
// Returns an error if something went wrong at the network level, or when
// parsing the response headers.
// In addition to LookupTXT it supports timeouts, cancellation and context propagation.
func (r *Resolver) LookupSRVCtx(ctx context.Context, fqdn string) (recs []*SRVRecord, ttls []uint32, err error) {
	answers, err := r.lookup(ctx, fqdn, SRV, IN)
	if err != nil {
		return
	}

	recs = make([]*SRVRecord, 0)
	ttls = make([]uint32, 0)

	for _, a := range answers {
		if a.t == SRV {
			recs = append(recs, a.parsed.(*SRVRecord))
			ttls = append(ttls, a.ttl)
		}
	}

	return
}

// LookupSRV performs a DoH lookup on SRV records for the given FQDN.
// Return records and TTLs such that ttls[0] is the TTL for recs[0], and so on.
// Returns an error if something went wrong at the network level, or when
// parsing the response headers.
func (r *Resolver) LookupSRV(fqdn string) (recs []*SRVRecord, ttls []uint32, err error) {
	return r.LookupSRVCtx(context.Background(), fqdn)
}

// LookupServiceCtx performs a DoH lookup on SRV records for the given service,
// network and domain. network's value is expected to be in the likes of "udp",
// "tcp" and so on. Under the hood, it builds a FQDN of the form
// _service._network.domain and calls r.LookupSRV with it.
// Return records and TTLs such that ttls[0] is the TTL for recs[0], and so on.
// Returns an error if something went wrong at the network level, or when
// parsing the response headers.
// In addition to LookupService it supports timeouts, cancellation and context propagation.
func (r *Resolver) LookupServiceCtx(ctx context.Context, service, network, domain string) (recs []*SRVRecord, ttls []uint32, err error) {
	return r.LookupSRVCtx(ctx, "_"+service+"._"+network+"."+domain)
}

// LookupService performs a DoH lookup on SRV records for the given service,
// network and domain. network's value is expected to be in the likes of "udp",
// "tcp" and so on. Under the hood, it builds a FQDN of the form
// _service._network.domain and calls r.LookupSRV with it.
// Return records and TTLs such that ttls[0] is the TTL for recs[0], and so on.
// Returns an error if something went wrong at the network level, or when
// parsing the response headers.
func (r *Resolver) LookupService(service, network, domain string) (recs []*SRVRecord, ttls []uint32, err error) {
	return r.LookupSRVCtx(context.Background(), "_"+service+"._"+network+"."+domain)
}

// LookupSOACtx performs a DoH lookup on SOA records for the given FQDN.
// Return records and TTLs such that ttls[0] is the TTL for recs[0], and so on.
// Returns an error if something went wrong at the network level, or when
// parsing the response headers.
// In addition to LookupSOA it supports timeouts, cancellation and context propagation.
func (r *Resolver) LookupSOACtx(ctx context.Context, fqdn string) (recs []*SOARecord, ttls []uint32, err error) {
	answers, err := r.lookup(ctx, fqdn, SOA, IN)
	if err != nil {
		return
	}

	recs = make([]*SOARecord, 0)
	ttls = make([]uint32, 0)

	for _, a := range answers {
		if a.t == SOA {
			recs = append(recs, a.parsed.(*SOARecord))
			ttls = append(ttls, a.ttl)
		}
	}

	return
}

// LookupSOA performs a DoH lookup on SOA records for the given FQDN.
// Return records and TTLs such that ttls[0] is the TTL for recs[0], and so on.
// Returns an error if something went wrong at the network level, or when
// parsing the response headers.
func (r *Resolver) LookupSOA(fqdn string) (recs []*SOARecord, ttls []uint32, err error) {
	return r.LookupSOACtx(context.Background(), fqdn)
}

// LookupPTRCtx performs a DoH lookup on PTR records for the given FQDN.
// Return records and TTLs such that ttls[0] is the TTL for recs[0], and so on.
// Returns an error if something went wrong at the network level, or when
// parsing the response headers.
// In addition to LookupPTR it supports timeouts, cancellation and context propagation.
func (r *Resolver) LookupPTRCtx(ctx context.Context, fqdn string) (recs []*PTRRecord, ttls []uint32, err error) {
	answers, err := r.lookup(ctx, fqdn, PTR, IN)
	if err != nil {
		return
	}

	recs = make([]*PTRRecord, 0)
	ttls = make([]uint32, 0)

	for _, a := range answers {
		if a.t == PTR {
			recs = append(recs, a.parsed.(*PTRRecord))
			ttls = append(ttls, a.ttl)
		}
	}

	return
}

// LookupPTR performs a DoH lookup on PTR records for the given FQDN.
// Return records and TTLs such that ttls[0] is the TTL for recs[0], and so on.
// Returns an error if something went wrong at the network level, or when
// parsing the response headers.
func (r *Resolver) LookupPTR(fqdn string) (recs []*PTRRecord, ttls []uint32, err error) {
	return r.LookupPTRCtx(context.Background(), fqdn)
}
