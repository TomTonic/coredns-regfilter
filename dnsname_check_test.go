package filterlist

import "testing"

// TestIsStrictDNSQueryName verifies that DNS users get consistent RFC 1035 and
// IDNA validation before denylist evaluation.
//
// This test covers the dedicated query-name validation helper in the filterlist
// package.
//
// It asserts that valid LDH and ACE names are accepted while malformed labels,
// overlong names, and invalid ACE labels are rejected.
func TestIsStrictDNSQueryName(t *testing.T) {
	tests := []struct {
		name  string
		qname string
		want  bool
	}{
		{"accepts root label", ".", true},
		{"accepts simple domain", "example.com.", true},
		{"accepts mixed case", "WWW.Example.COM.", true},
		{"accepts 63-byte label", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com.", true},
		{"accepts valid ace label", "xn--bcher-kva.example.", true},
		{"rejects empty name", "", false},
		{"rejects leading hyphen", "-bad.example.com.", false},
		{"rejects trailing hyphen", "bad-.example.com.", false},
		{"rejects empty label", "a..example.com.", false},
		{"rejects underscore", "_dmarc.example.com.", false},
		{"rejects 64-byte label", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com.", false},
		{"rejects name longer than 253 bytes", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com.", false},
		{"rejects invalid ace label", "xn--garbage123456789.example.com.", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isStrictDNSQueryName(tt.qname)
			if got != tt.want {
				t.Errorf("isStrictDNSQueryName(%q) = %v, want %v", tt.qname, got, tt.want)
			}
		})
	}
}

// BenchmarkIsStrictDNSQueryNameASCII measures the pure ASCII fast path with no
// IDNA round-trip.
func BenchmarkIsStrictDNSQueryNameASCII(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !isStrictDNSQueryName("www.example.com.") {
			b.Fatal("expected valid name")
		}
	}
}

// BenchmarkIsStrictDNSQueryNameLongASCII measures the longest common-case path:
// valid ASCII input near the RFC label limit without IDNA.
func BenchmarkIsStrictDNSQueryNameLongASCII(b *testing.B) {
	name := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com."
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !isStrictDNSQueryName(name) {
			b.Fatal("expected valid name")
		}
	}
}

// BenchmarkIsStrictDNSQueryNameACE measures the slower path where an ACE label
// triggers an IDNA round-trip.
func BenchmarkIsStrictDNSQueryNameACE(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !isStrictDNSQueryName("xn--bcher-kva.example.") {
			b.Fatal("expected valid ace name")
		}
	}
}

// BenchmarkIsStrictDNSQueryNameRejectEarly measures how fast malformed labels
// are rejected on the ASCII scan path.
func BenchmarkIsStrictDNSQueryNameRejectEarly(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if isStrictDNSQueryName("_bad.example.com.") {
			b.Fatal("expected invalid name")
		}
	}
}
