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
		{"accepts dmarc underscore label", "_dmarc.example.com.", true},
		{"accepts dns-sd service enumeration", "lb._dns-sd._udp.example.com.", true},
		{"accepts srv style underscore labels", "_ldap._tcp.example.com.", true},
		{"accepts dkim selector underscore label", "selector1._domainkey.example.com.", true},
		{"rejects empty name", "", false},
		{"rejects leading hyphen", "-bad.example.com.", false},
		{"rejects trailing hyphen", "bad-.example.com.", false},
		{"rejects empty label", "a..example.com.", false},
		{"rejects mid-label underscore", "a_b.example.com.", false},
		{"rejects 64-byte label", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com.", false},
		{"rejects name longer than 253 bytes", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com.", false},
		{"rejects invalid ace label", "xn--garbage123456789.example.com.", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isStrictDNSQueryName(tt.qname, true)
			if got != tt.want {
				t.Errorf("isStrictDNSQueryName(%q, true) = %v, want %v", tt.qname, got, tt.want)
			}
		})
	}
}

// TestIsStrictDNSQueryNameRejectsUnderscoreWhenDisabled verifies that operators
// who enable strict_rfc_names get the original strict RFC 1035 behavior, where
// any underscore label is rejected.
//
// This test covers the allowUnderscoreLabels parameter of the query-name
// validation helper in the filterlist package.
//
// It asserts that DNS-SD and other underscored names that are accepted with the
// flag enabled are rejected when it is disabled, while ordinary LDH names are
// still accepted.
func TestIsStrictDNSQueryNameRejectsUnderscoreWhenDisabled(t *testing.T) {
	tests := []struct {
		name  string
		qname string
		want  bool
	}{
		{"rejects dmarc underscore label", "_dmarc.example.com.", false},
		{"rejects dns-sd service enumeration", "lb._dns-sd._udp.example.com.", false},
		{"rejects srv style underscore labels", "_ldap._tcp.example.com.", false},
		{"still accepts plain ldh name", "example.com.", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isStrictDNSQueryName(tt.qname, false)
			if got != tt.want {
				t.Errorf("isStrictDNSQueryName(%q, false) = %v, want %v", tt.qname, got, tt.want)
			}
		})
	}
}

// BenchmarkIsStrictDNSQueryNameASCII measures the pure ASCII fast path with no
// IDNA round-trip.
func BenchmarkIsStrictDNSQueryNameASCII(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !isStrictDNSQueryName("www.example.com.", true) {
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
		if !isStrictDNSQueryName(name, true) {
			b.Fatal("expected valid name")
		}
	}
}

// BenchmarkIsStrictDNSQueryNameACE measures the slower path where an ACE label
// triggers an IDNA round-trip.
func BenchmarkIsStrictDNSQueryNameACE(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !isStrictDNSQueryName("xn--bcher-kva.example.", true) {
			b.Fatal("expected valid ace name")
		}
	}
}

// BenchmarkIsStrictDNSQueryNameRejectEarly measures how fast malformed labels
// are rejected on the ASCII scan path.
func BenchmarkIsStrictDNSQueryNameRejectEarly(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if isStrictDNSQueryName("-bad.example.com.", true) {
			b.Fatal("expected invalid name")
		}
	}
}
