# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **`action nullip` now returns NODATA instead of NXDOMAIN for non-A/AAAA queries (#38)**: Previously `nullip` synthesized `A`/`AAAA` sinkhole answers but replied with NXDOMAIN for all other query types (PTR, HTTPS/SVCB, TXT, MX, SRV, ...). NXDOMAIN asserts the whole name is nonexistent (RFC 8020), so RFC 8020-aware resolvers could negative-cache the name and poison the A/AAAA sinkhole answers (browsers query HTTPS/SVCB in parallel with A/AAAA), and some stub resolvers re-queried aggressively instead of backing off. `nullip` now returns an empty `NOERROR` response (NODATA) for those types, giving consistent "name exists, no record of this type" semantics. The `nxdomain` and `refuse` actions are unchanged.

### Changed
- **Metrics overhaul (breaking)**: Reworked the Prometheus metric set for clearer operational signal.
  - Added `coredns_filterlist_queries_total{result=...}`, a single counter incremented exactly once per query. The `result` label distinguishes `allowlisted`, `forwarded`, `blocked_denylist`, `blocked_rfc`, and `blocked_unlisted`, so block volume can now be broken down by reason.
  - Added `coredns_filterlist_allowlist_states` and `coredns_filterlist_denylist_states` gauges exposing the compiled matcher state counts (memory/complexity proxy) that were previously only written to the compile log.
  - Changed `coredns_filterlist_match_duration_seconds` from a summary to a histogram and reduced its `result` label to `forwarded`/`blocked`; retuned the buckets to the microsecond matching range.
  - Retuned `coredns_filterlist_compile_duration_seconds` buckets to span 0.05s–51s.
  - **Removed** `coredns_filterlist_allowlist_checks_total`, `coredns_filterlist_denylist_checks_total`, `coredns_filterlist_allowlist_hits_total`, and `coredns_filterlist_denylist_hits_total`. The checks counters carried little signal and the hits counters are subsumed by `queries_total`. Dashboards and alerts referencing these names must migrate to `queries_total{result=...}`.

## [v0.1.0] - 2026-04-04

### Features
- **Filter list support**: Parses AdGuard, EasyList, ABP, and hosts-style filter lists
- **Selectable matcher mode**: default hybrid mode uses a suffix map for literals plus a DFA for wildcards; `matcher_mode dfa` compiles all rules into one DFA
- **Ultra fast**: about 200ns (0.0002ms) latency per query, less than 5s for full compilation/DFA construction for standard AdGuard DNS filter list (.5s compilation time for hybrid mode)
- **Hot reload**: Watches filter list directories and recompiles matchers on changes
- **Allowlist precedence**: Domains in the allowlist are always allowed, even if blacklisted
- **Multiple block actions**: NXDOMAIN, REFUSE, or null IP responses
- **RFC / IDNA name validation**: Blocks queries whose names violate RFC rules (can be disabled)
- **Deny-non-allowlisted mode**: Optionally blocks every query not present in the allowlist (default: off)
- **Observability**: Prometheus metrics and structured logging
