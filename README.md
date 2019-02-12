# go-doh-client

[![Build Status](https://travis-ci.org/babolivier/go-doh-client.svg?branch=master)](https://travis-ci.org/babolivier/go-doh-client) [![GoDoc](https://godoc.org/github.com/babolivier/go-doh-client?status.svg)](https://godoc.org/github.com/babolivier/go-doh-client) [![Go Report Card](https://goreportcard.com/badge/github.com/babolivier/go-doh-client)](https://goreportcard.com/report/github.com/babolivier/go-doh-client)

This is a Go implementation of a DNS over HTTPS
([RFC8484](https://tools.ietf.org/html/rfc8484)) client library.

It doesn't currently implement all of the DNS specifications. It implements
looking up the following records:

* A
* AAAA
* CNAME
* MX
* NS
* TXT
* SRV

More will come in the future (such as SOA and AXFR).

It also currently doesn't other query types than standard query, nor support for
truncated messages. Full compliance, at least with [RFC
1035](https://tools.ietf.org/html/rfc1035), is something I'd like, though, so
all of that should come in the future..

## Usage

This client library should be as easy to use as any other DNS client library.
The only difference is the transport layer it uses to perform lookups.

Here's a quick example:

```go
package main

import (
	"log"

	"github.com/babolivier/go-doh-client"
)

func main() {
	resolver := doh.Resolver{
		Host:  "9.9.9.9", // Change this with your favourite DoH-compliant resolver.
		Class: doh.IN,
	}

	// Perform a A lookup on example.com
	a, _, err := resolver.LookupA("example.com")
	if err != nil {
		panic(err)
	}
	println(a[0].IP4) // 93.184.216.34

	// Perform a SRV lookup for e.g. a Matrix homeserver
	srv, _, err := resolver.LookupService("matrix", "tcp", "example.com")
	if err != nil {
		panic(err)
	}
	println(a[0].Target) // matrix.example.com
}
```

## Why?

I grew quite interested in how the Internet works lately, which implies spending
some time reading DNS-related RFCs. On top of that, DNS over HTTPS is something
I'm interested in quite a lot for privacy reasons and because of how harder it
is to censor than classic DNS, so I decided to give it a go. And also because my
definition of "having fun during holidays" obviously involves implementing part
of the DNS RFC.
