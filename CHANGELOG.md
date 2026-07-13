# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Each entry aggregates everything that changed since the previous release,
grouped per the release-notes guidelines in `AGENTS.md`.

## [v0.4.0] - 2026-07-13

### New Features
- **Negative-caching SOA on NXDOMAIN and NODATA responses (#38)**: Blocked responses that carry no answer — the `nxdomain` action and the `nullip` NODATA replies — now include an authority-section SOA (RFC 2308) whose TTL and Minimum are set to the configured `ttl`. Without it the negative-cache lifetime was undefined, so some stub resolvers re-queried aggressively instead of backing off. `refuse` responses deliberately carry no SOA. The `ttl` option therefore now also governs the negative-caching lifetime of `nxdomain`/NODATA responses, not just `nullip` answers.
- **Synthesized HTTPS/SVCB sinkhole records for `nullip` (#38)**: `HTTPS` (type 65) and `SVCB` (type 64) queries for a blocked name now return a ServiceMode record whose `ipv4hint`/`ipv6hint` point at the configured sinkhole addresses, instead of NODATA. Browsers query HTTPS in parallel with A/AAAA, so this steers them directly to the sinkhole rather than relying on A/AAAA fallback.

### Changed Behavior
- **`action nullip` now returns NODATA instead of NXDOMAIN for non-A/AAAA queries (#38)**: Previously `nullip` synthesized `A`/`AAAA` sinkhole answers but replied with NXDOMAIN for all other query types (PTR, HTTPS/SVCB, TXT, MX, SRV, ...). NXDOMAIN asserts the whole name is nonexistent (RFC 8020), so RFC 8020-aware resolvers could negative-cache the name and poison the A/AAAA sinkhole answers, and some stub resolvers re-queried aggressively instead of backing off. `nullip` now returns an empty `NOERROR` response (NODATA) for those types, giving consistent "name exists, no record of this type" semantics. The `nxdomain` and `refuse` actions are unchanged.

## [v0.3.2] - 2026-07-12

### Source Code Updates
- Bumped the Go toolchain to 1.25.12 and `github.com/coredns/coredns` to v1.14.6, `golang.org/x/net` to v0.57.0, and other indirect Go module dependencies.

### CI Updates
- Routine Renovate-managed action bumps: `schneegans/dynamic-badges-action` to v1.9.0, `github/codeql-action` to v4.37.0, and `step-security/harden-runner` to v2.20.0.

## [v0.3.1] - 2026-06-27

### Source Code Updates
- Bumped indirect dependencies `github.com/prometheus/procfs` to v0.21.0 and `golang.org/x/tools` to v0.47.0.

## [v0.3.0] - 2026-06-23

### New Features
- **`strict_rfc_names` directive (#29)**: The RFC 1035 query-name precheck now accepts RFC 8553 underscored labels (DNS-SD per RFC 6763, e.g. `lb._dns-sd._udp.example.com`, plus DKIM, DMARC, and SRV names) by default — a single leading underscore per label is permitted, mid-label underscores are still rejected. Set `strict_rfc_names on` to restore strict RFC 1035 LDH validation that rejects any underscore. Note that enabling it applies globally to all underscored names, not just a specific domain; use denylist rules instead to block underscored names for one domain only.

### Changed Behavior
- **RFC precheck no longer blocks DNS-SD/DKIM/DMARC/SRV names by default (#29)**: Names with a single leading underscore per label, previously rejected with `reason=RFC_name_violation`, are now allowed unless `strict_rfc_names` is enabled.

### Source Code Updates
- Updated indirect Go module dependencies to their latest versions.

### CI Updates
- Bumped `actions/checkout` to v7.0.0. Renovate config now excludes `coredns/caddy` from automated updates so upgrades of the core CoreDNS dependency get manual review.

## [v0.2.0] - 2026-06-14

### New Features
- **`log_queries` directive**: New canonical name for enabling per-query outcome logging (blocked/allowlisted/forwarded with rule attribution). The old `debug` keyword is kept as a deprecated backwards-compatible alias; existing Corefiles continue to work unchanged.
- **Setup-time configuration warnings**: CoreDNS now warns at startup when `deny_non_allowlisted` is configured without an `allowlist_dir` (which silently blocks every query), in addition to the existing `max_states=0` warning.

### Changed Behavior (breaking)
- **Metrics overhaul**: Reworked the Prometheus metric set for clearer operational signal.
  - Added `coredns_filterlist_queries_total{result=...}`, a single counter incremented exactly once per query. The `result` label distinguishes `allowlisted`, `forwarded`, `blocked_denylist`, `blocked_rfc`, and `blocked_unlisted`, so block volume can now be broken down by reason.
  - Added `coredns_filterlist_allowlist_states` and `coredns_filterlist_denylist_states` gauges exposing the compiled matcher state counts (memory/complexity proxy) that were previously only written to the compile log.
  - Changed `coredns_filterlist_match_duration_seconds` from a summary to a histogram and reduced its `result` label to `forwarded`/`blocked`; retuned the buckets to the microsecond matching range.
  - Retuned `coredns_filterlist_compile_duration_seconds` buckets to span 0.05s-51s.
  - **Removed** `coredns_filterlist_allowlist_checks_total`, `coredns_filterlist_denylist_checks_total`, `coredns_filterlist_allowlist_hits_total`, and `coredns_filterlist_denylist_hits_total`. The checks counters carried little signal and the hits counters are subsumed by `queries_total`. Dashboards and alerts referencing these names must migrate to `queries_total{result=...}`.
  - All `queries_total` result series and `match_duration_seconds` latency series are now pre-initialized to zero at registry creation, so `rate()` queries are well-defined and every outcome is discoverable on a fresh instance.
- **Internal log volume reduced**: Raw fsnotify filesystem events and DFA compile-progress messages are now emitted at `[DEBUG]` level (visible only with `--debug`) instead of `[INFO]`, since the compile-summary line already covers reload outcomes. Operational log volume during list updates drops from dozens of lines to that single line.

### Architectural Changes
- **Atomic list-state snapshots**: The per-list matcher, rule sources, and rule patterns are now consolidated into a single atomically-published `listState` so the DNS hot path always reads a self-consistent snapshot; debug rule attribution can no longer mismatch metadata against a concurrently reloaded matcher.
- **Watcher shutdown correctness**: The watcher's recovery-rebuild goroutine is now tracked in its `WaitGroup` and checks the shutdown context, so `stop()` waits for it and it can no longer publish a stale snapshot after shutdown.

## [v0.1.5] - 2026-06-11

### Source Code Updates
- Updated Go module dependencies.

## [v0.1.4] - 2026-06-08

### Source Code Updates
- Bumped the Go toolchain to 1.25.11 and indirect dependencies `golang.org/x/net` to v0.55.0, `golang.org/x/crypto` to v0.52.0, and `google.golang.org/genproto/googleapis/rpc`.

### CI Updates
- CI now passes `check-latest: true` to `actions/setup-go` so the latest available Go patch release is always used during setup, not a cached older one.
- Bumped `github/codeql-action` to v4.36.0, `step-security/harden-runner` to v2.19.4, and other GitHub Actions patch versions.

## [v0.1.3] - 2026-05-16

### Changed Behavior
- **Fixed inconsistent wildcard label validation**: The pattern-label validator applied different rules to labels containing `*` than to plain labels, so some malformed wildcard labels (e.g. leading/trailing hyphens) could slip past validation while equivalent plain labels were rejected. Wildcard and plain labels are now validated by the same character-class and hyphen-boundary checks.

### Source Code Updates
- Bumped the Go toolchain to 1.25.10 and updated dependencies.

### CI Updates
- Bumped `github/codeql-action` to v4.35.5 and `step-security/harden-runner` to v2.19.3.

## [v0.1.2] - 2026-05-12

### Source Code Updates
- Updated `github.com/fsnotify/fsnotify` to v1.10.1 and `golang.org/x/net` to v0.54.0.

### CI Updates
- Bumped `actions/dependency-review-action` to v5 and other GitHub Actions patch versions.

## [v0.1.1] - 2026-04-25

### Source Code Updates
- Bumped the Go toolchain to 1.25.9 and `github.com/coredns/coredns` to v1.14.3, `golang.org/x/net` to v0.53.0, and other indirect dependencies.

### CI Updates
- Bumped `step-security/harden-runner` to v2.19.0, `softprops/action-gh-release` to v3, and other GitHub Actions patch/major versions.

## [v0.1.0] - 2026-04-04

### New Features
- **Filter list support**: Parses AdGuard, EasyList, ABP, and hosts-style filter lists
- **Selectable matcher mode**: default hybrid mode uses a suffix map for literals plus a DFA for wildcards; `matcher_mode dfa` compiles all rules into one DFA
- **Ultra fast**: about 200ns (0.0002ms) latency per query, less than 5s for full compilation/DFA construction for standard AdGuard DNS filter list (.5s compilation time for hybrid mode)
- **Hot reload**: Watches filter list directories and recompiles matchers on changes
- **Allowlist precedence**: Domains in the allowlist are always allowed, even if blacklisted
- **Multiple block actions**: NXDOMAIN, REFUSE, or null IP responses
- **RFC / IDNA name validation**: Blocks queries whose names violate RFC rules (can be disabled)
- **Deny-non-allowlisted mode**: Optionally blocks every query not present in the allowlist (default: off)
- **Observability**: Prometheus metrics and structured logging
</content>
