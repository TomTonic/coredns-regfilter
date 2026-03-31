# Design Document

## Overview

`coredns-regfilter` is a CoreDNS plugin for DNS-layer domain filtering. It
loads supported host-based rules from whitelist and blacklist directories,
compiles them into deterministic finite automata (DFAs), and evaluates DNS
queries against those DFAs on the request path.

The design goal is not to implement a full browser filter engine. The plugin
focuses on the subset of AdGuard, EasyList, and hosts-style syntax that can be
reduced to a pure domain decision at DNS time.

The most important properties are:

- predictable O(n) matching on the request path;
- atomic hot reloads without locking the hot path;
- fail-open behavior when a reload fails or a directory is temporarily broken;
- enough source metadata to explain matches in logs and offline tooling.

## Architectural Focus

This document focuses on the runtime system behavior:

- how the plugin is inserted into the CoreDNS handler chain;
- how rules flow from files into compiled snapshots;
- how whitelist and blacklist semantics are derived from directory context;
- how reload failures, empty lists, and debug output are handled.

The DFA construction details still matter, but they are an implementation
mechanism rather than the primary architectural story.

## Runtime Architecture

```text
query
       |
       v
regfilter ServeDNS
       |
       +--> whitelist snapshot -> match? yes -> next plugin
       |
       +--> blacklist snapshot -> match? yes -> blocked response
       |
       +--> no match -> next plugin

watcher
       |
       +--> fsnotify + debounce
       |
       +--> LoadDirectory
       |
       +--> rule selection
       |      - blacklist: keep deny rules only
       |      - whitelist: keep allow rules by default
       |      - whitelist + invert_whitelist: keep deny-style rules
       |
       +--> CompileRules
       |
       +--> Snapshot{DFA, rule count, state count, sources, patterns}
       |
       +--> atomic swap of active whitelist / blacklist snapshots
```

Two details are easy to miss but central to the design:

- `regfilter` only sees queries if it appears early enough in the generated CoreDNS plugin chain, and in practice it must run before terminal plugins such as `forward`.
- The runtime does not swap raw DFAs alone; it swaps a snapshot that also carries rule count, source file references, and original patterns for logging and diagnostics.

## CoreDNS Integration

The plugin is configured from a Corefile stanza, but the effective execution
order comes from the generated CoreDNS plugin chain derived from `plugin.cfg`.

That distinction matters because:

- Corefile stanza order does not control which plugin runs first;
- `regfilter` must be inserted before `forward` in the generated chain;
- if `forward` runs first, `regfilter` may initialize successfully but never see live queries, so it cannot filter or emit per-query debug logs.

The plugin emits a startup warning when it detects that `forward` appears
before `regfilter` in the constructed handler chain.

## Rule Ingestion and Selection

### File Loading

The watcher loads directories non-recursively through `blockloader`.

- supported files are parsed and aggregated;
- unreadable files are logged and skipped;
- unreadable directories cause the directory compile to fail;
- extension filtering happens before parsing.

`blockloader` delegates file parsing to `filterlist.ParseFile`, which produces
canonical `filterlist.Rule` values.

### Canonical Rule Model

Each parsed rule carries:

- `Pattern`: canonical domain pattern used for automaton compilation;
- `Source`: `path:line` for diagnostics and debug logging;
- `IsAllow`: whether the source rule was an exception rule (`@@...`).

This is important because allow-versus-block semantics are not determined only
by the text of the rule. They are also shaped by the directory being compiled.

### Directory-Specific Semantics

After parsing and before DFA compilation, the watcher filters rules based on
which directory is being compiled.

Blacklist directory:

- only non-allow rules are compiled;
- `@@` exception rules are excluded automatically;
- downloaded AdGuard or EasyList lists work without conversion.

Whitelist directory, default behavior:

- only `@@` exception rules are compiled;
- this follows AdGuard-style semantics where `@@` means allow.

Whitelist directory, `invert_whitelist` enabled:

- non-`@@` rules are compiled instead;
- this allows simpler `||domain^` syntax in whitelist files.

This rule-selection step is a real architectural stage and should be thought of
as part of the compile pipeline, not as a parser detail.

## Compilation Pipeline

For each directory, the watcher executes this pipeline:

1. load and parse all supported files;
2. filter the resulting rules for whitelist or blacklist semantics;
3. compile the selected rules with `automaton.CompileRules`;
4. build a snapshot containing DFA, rule count, state count, sources, and patterns;
5. publish the new snapshot atomically if compilation succeeded.

The automaton compiler currently uses:

- Thompson-style NFA construction for individual patterns;
- NFA combination into a single machine;
- subset construction to build a DFA;
- Hopcroft minimization by default;
- a cache-friendly array-based DFA representation for runtime matching.

That internal pipeline is useful to know, but the externally visible contract
is simpler: a directory compile either yields a new immutable snapshot or the
previous active snapshot remains in place.

## Hot Reload and Failure Model

The watcher listens for filesystem changes, debounces them, and recompiles only
the affected directory snapshot.

```text
fsnotify event -> debounce -> load/parse -> rule selection -> compile -> atomic swap
```

The reload model is intentionally fail-open:

- if a reload fails, the last successful snapshot for that directory stays active;
- if a directory becomes empty or yields no supported rules, that directory's
       active DFA becomes empty for the next successful snapshot;
- startup does not fail just because a configured directory is empty or contains
       only unsupported rules;
- startup fails only when the watcher infrastructure itself cannot be started.

This makes the operational tradeoff explicit: preserve service continuity and
prefer stale-but-known-good policy over blocking DNS because of transient list
problems.

## Query Path

The request path is intentionally short:

1. normalize the queried name to lowercase without the trailing root dot;
2. match against the active whitelist DFA;
3. if matched, allow the query to continue to the next plugin;
4. otherwise match against the active blacklist DFA;
5. if matched, synthesize the configured blocked response;
6. otherwise forward unchanged to the next plugin.

The plugin stores the currently active DFA snapshots in atomic state, so the
hot path performs no lock acquisition.

## Response Modes

Blacklist hits can produce three behaviors:

- `nxdomain`: return NXDOMAIN;
- `refuse`: return REFUSED;
- `nullip`: return synthetic `A` and `AAAA` answers for address lookups and
       NXDOMAIN for other query types.

Whitelist hits never synthesize an answer. They simply permit the query to
continue to the next plugin.

## Debugging and Match Attribution

The design now treats operator visibility as part of the runtime model, not as
an afterthought.

For that reason, the active snapshots retain:

- source file and line information;
- canonical pattern strings.

When `debug` is enabled:

- blacklist matches log the matching list, normalized name, source, and pattern;
- whitelist matches log the same information;
- unmatched queries log `no match`.

This is why the snapshot contains more than just the DFA pointer.

## Resource Limits

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `max_states` | 200000 | Bounds DFA size to limit memory growth |
| `compile_timeout` | `30s` | Bounds per-directory compile time |
| `debounce` | `300ms` | Coalesces bursts of file changes |

These limits are operational safeguards. They are not intended to make every
pathological filter list safe, but they keep failure modes bounded and visible.

## Performance Characteristics

- matching is O(n) in the query name length;
- the hot path uses immutable snapshots and atomic reads only;
- compile cost depends on the selected rule set and DFA minimization work;
- memory use is dominated by DFA state count plus the retained source metadata.

The exact compile complexity is intentionally not specified more tightly here,
because the subset-construction and minimization steps depend heavily on the
shape of the input rule set.

### Measured Reference Scenario

The repository contains two realistic upstream-style sample lists in
`testdata/filterlists/Adguard_filter_example.txt` and
`testdata/filterlists/easylistgermany_example.txt`.

Measured together as one blacklist directory on the current development
machine (`linux/amd64`, Go `1.26.1`, AMD Ryzen 9 7900), with blacklist rule
selection applied and `max_states=0` to observe the uncapped compile:

- parsed blacklist rules: 160798
- compiled DFA states: 2273841
- end-to-end parse plus compile wall-clock time: 4m18.67s
- peak resident memory during that run: 9964356 KiB (about 9.5 GiB)

Two practical conclusions follow from that measurement:

- this combined sample pair is far above the default `max_states=200000` limit;
- large real-world lists can produce much more temporary allocation traffic
       during compilation than their final resident DFA footprint suggests.

For reproducible benchmarking in the repository, see
`BenchmarkCompileRealisticBlacklist` and
`BenchmarkParseAndCompileRealisticBlacklist` in `realworld_bench_test.go`.

## Metrics and Logging

All metrics are exported with the `coredns_regfilter_` prefix.

### Query Metrics

| Metric | Type | Meaning |
|--------|------|---------|
| `whitelist_checks_total` | Counter | Queries evaluated against the whitelist DFA |
| `blacklist_checks_total` | Counter | Queries evaluated against the blacklist DFA |
| `whitelist_hits_total` | Counter | Queries accepted because the whitelist matched |
| `blacklist_hits_total` | Counter | Queries blocked because the blacklist matched |
| `match_duration_seconds{result=...}` | Summary | End-to-end plugin matching duration |

`match_duration_seconds` uses these `result` labels:

- `accept`: whitelist matched and query continued;
- `reject`: blacklist matched and query was blocked;
- `pass`: no rule matched and query continued unchanged.

### Compile and State Metrics

| Metric | Type | Meaning |
|--------|------|---------|
| `compile_errors_total` | Counter | Failed directory load or compile runs |
| `compile_duration_seconds` | Histogram | Distribution of successful directory compile durations |
| `last_compile_timestamp_seconds` | Gauge | Timestamp of the most recent successful compile |
| `last_compile_duration_seconds` | Gauge | Duration of the most recent successful compile |
| `whitelist_rules` | Gauge | Current number of compiled whitelist rules |
| `blacklist_rules` | Gauge | Current number of compiled blacklist rules |

The rule gauges count compiled rules, not DFA states.

In addition to metrics, every compile attempt emits a structured summary log
that includes label, directory, outcome, rule count, state count, duration, and
any error.

## Non-Goals

The current design explicitly does not attempt to support:

- browser-side cosmetic rules;
- request-type or first-party/third-party semantics;
- URL path filtering;
- full ABP or AdGuard modifier semantics;
- recursive directory trees or remote list fetching inside the plugin.

Those features would require a different execution model than pure DNS name
matching and would change the core architecture substantially.
