// Package validate is the pre-network safety gate. It validates a scan URL
// (scheme, host, no control characters or CRLF) and a result/screenshot UUID
// (RFC 4122 form) before any value is placed into an HTTP request, so
// malformed or injection-bearing input never reaches urlscan.io.
package validate
