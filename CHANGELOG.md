# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
