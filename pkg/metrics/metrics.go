// Package metrics provides Prometheus metrics helpers for the filterlist plugin.
package metrics

import (
	"errors"
	"log"

	"github.com/prometheus/client_golang/prometheus"
)

// Query outcome label values for the Queries counter.
//
// Each query produces exactly one of these results, so summing the counter
// over all label values yields the total number of queries handled, and the
// individual series answer "how many were blocked and why".
const (
	// ResultAllowlisted marks a query that matched the allowlist and was forwarded.
	ResultAllowlisted = "allowlisted"
	// ResultForwarded marks a query that matched no rule and was forwarded unchanged.
	ResultForwarded = "forwarded"
	// ResultBlockedDenylist marks a query blocked by the denylist matcher.
	ResultBlockedDenylist = "blocked_denylist"
	// ResultBlockedRFC marks a query blocked by the RFC 1035 / IDNA name check.
	ResultBlockedRFC = "blocked_rfc"
	// ResultBlockedUnlisted marks a query blocked by the deny_non_allowlisted policy.
	ResultBlockedUnlisted = "blocked_unlisted"
)

// Match latency label values for the MatchDuration histogram.
//
// Latency is split only into the two coarse outcomes that matter for the
// request path: a forwarded query traverses the full matcher chain, while a
// blocked query short-circuits as soon as a rule decides the answer.
const (
	// LatencyForwarded labels latency of queries that were forwarded.
	LatencyForwarded = "forwarded"
	// LatencyBlocked labels latency of queries that were blocked.
	LatencyBlocked = "blocked"
)

// Registry groups the Prometheus collectors used by filterlist.
//
// The collectors fall into two groups: request-path decisions (Queries,
// MatchDuration) and ruleset/compile health (the gauges, CompileDuration, and
// CompileErrors). Callers usually create one Registry per process or per
// Prometheus registerer and share it across handler instances.
type Registry struct {
	// Queries counts every handled query, labeled by result (see Result* constants).
	Queries *prometheus.CounterVec
	// MatchDuration records per-query matching latency, labeled by Latency* constants.
	MatchDuration *prometheus.HistogramVec

	CompileErrors   prometheus.Counter
	CompileDuration prometheus.Histogram

	AllowlistRules  prometheus.Gauge
	DenylistRules   prometheus.Gauge
	AllowlistStates prometheus.Gauge
	DenylistStates  prometheus.Gauge

	LastCompileTimestamp       prometheus.Gauge
	LastCompileDurationSeconds prometheus.Gauge
}

// NewRegistry creates a filterlist metric set on prometheus.DefaultRegisterer.
//
// The returned Registry reuses already-registered collectors when another
// filterlist instance has already published the same metric names. Use this in
// CoreDNS plugin setup paths where multiple server blocks may instantiate the
// plugin within the same process.
func NewRegistry() *Registry {
	return NewRegistryWith(prometheus.DefaultRegisterer)
}

// NewRegistryWith creates a filterlist metric set on reg.
//
// The reg parameter selects the Prometheus registerer that should own the
// metrics. When reg already contains collectors with the same metric
// descriptors, the existing collectors are reused instead of causing a panic.
// This keeps repeated setup calls safe while preserving shared metric series.
func NewRegistryWith(reg prometheus.Registerer) *Registry {
	r := &Registry{
		Queries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "coredns",
			Subsystem: "filterlist",
			Name:      "queries_total",
			Help:      "Total number of DNS queries handled, by result (allowlisted, forwarded, blocked_denylist, blocked_rfc, blocked_unlisted).",
		}, []string{"result"}),
		MatchDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "coredns",
			Subsystem: "filterlist",
			Name:      "match_duration_seconds",
			Help:      "Per-query matching latency in seconds, by outcome (forwarded, blocked).",
			// Matching is in the microsecond range; buckets span 1us to ~180ms.
			Buckets: prometheus.ExponentialBuckets(1e-6, 3, 12),
		}, []string{"result"}),
		CompileErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "coredns",
			Subsystem: "filterlist",
			Name:      "compile_errors_total",
			Help:      "Total number of failed filter load or compile runs.",
		}),
		CompileDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "coredns",
			Subsystem: "filterlist",
			Name:      "compile_duration_seconds",
			Help:      "Duration of DFA compilation in seconds.",
			// Compiles range from tens of milliseconds to tens of seconds.
			Buckets: prometheus.ExponentialBuckets(0.05, 2, 11),
		}),
		AllowlistRules: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "coredns",
			Subsystem: "filterlist",
			Name:      "allowlist_rules",
			Help:      "Current number of compiled allowlist rules.",
		}),
		DenylistRules: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "coredns",
			Subsystem: "filterlist",
			Name:      "denylist_rules",
			Help:      "Current number of compiled denylist rules.",
		}),
		AllowlistStates: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "coredns",
			Subsystem: "filterlist",
			Name:      "allowlist_states",
			Help:      "Current number of states in the compiled allowlist matcher (memory/complexity proxy).",
		}),
		DenylistStates: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "coredns",
			Subsystem: "filterlist",
			Name:      "denylist_states",
			Help:      "Current number of states in the compiled denylist matcher (memory/complexity proxy).",
		}),
		LastCompileTimestamp: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "coredns",
			Subsystem: "filterlist",
			Name:      "last_compile_timestamp_seconds",
			Help:      "Unix timestamp of the last successful DFA compilation.",
		}),
		LastCompileDurationSeconds: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "coredns",
			Subsystem: "filterlist",
			Name:      "last_compile_duration_seconds",
			Help:      "Duration of the most recent DFA compilation in seconds.",
		}),
	}

	r.Queries = registerCounterVec(reg, r.Queries)
	r.MatchDuration = registerHistogramVec(reg, r.MatchDuration)
	r.CompileErrors = registerCounter(reg, r.CompileErrors)
	r.CompileDuration = registerHistogram(reg, r.CompileDuration)
	r.AllowlistRules = registerGauge(reg, r.AllowlistRules)
	r.DenylistRules = registerGauge(reg, r.DenylistRules)
	r.AllowlistStates = registerGauge(reg, r.AllowlistStates)
	r.DenylistStates = registerGauge(reg, r.DenylistStates)
	r.LastCompileTimestamp = registerGauge(reg, r.LastCompileTimestamp)
	r.LastCompileDurationSeconds = registerGauge(reg, r.LastCompileDurationSeconds)

	return r
}

// registerCounter registers a Counter or reuses an existing one with the same descriptor.
func registerCounter(reg prometheus.Registerer, collector prometheus.Counter) prometheus.Counter {
	if err := reg.Register(collector); err != nil {
		var alreadyRegistered prometheus.AlreadyRegisteredError
		if errors.As(err, &alreadyRegistered) {
			if existing, ok := alreadyRegistered.ExistingCollector.(prometheus.Counter); ok {
				return existing
			}
			log.Printf("filterlist metrics: collector type mismatch for counter reuse: %v", err)
			return collector
		}
		log.Printf("filterlist metrics: failed to register counter: %v", err)
	}

	return collector
}

// registerCounterVec registers a CounterVec or reuses an existing one with the same descriptor.
func registerCounterVec(reg prometheus.Registerer, collector *prometheus.CounterVec) *prometheus.CounterVec {
	if err := reg.Register(collector); err != nil {
		var alreadyRegistered prometheus.AlreadyRegisteredError
		if errors.As(err, &alreadyRegistered) {
			if existing, ok := alreadyRegistered.ExistingCollector.(*prometheus.CounterVec); ok {
				return existing
			}
			log.Printf("filterlist metrics: collector type mismatch for counter vector reuse: %v", err)
			return collector
		}
		log.Printf("filterlist metrics: failed to register counter vector: %v", err)
	}

	return collector
}

// registerGauge registers a Gauge or reuses an existing one with the same descriptor.
func registerGauge(reg prometheus.Registerer, collector prometheus.Gauge) prometheus.Gauge {
	if err := reg.Register(collector); err != nil {
		var alreadyRegistered prometheus.AlreadyRegisteredError
		if errors.As(err, &alreadyRegistered) {
			if existing, ok := alreadyRegistered.ExistingCollector.(prometheus.Gauge); ok {
				return existing
			}
			log.Printf("filterlist metrics: collector type mismatch for gauge reuse: %v", err)
			return collector
		}
		log.Printf("filterlist metrics: failed to register gauge: %v", err)
	}

	return collector
}

// registerHistogram registers a Histogram or reuses an existing one with the same descriptor.
func registerHistogram(reg prometheus.Registerer, collector prometheus.Histogram) prometheus.Histogram {
	if err := reg.Register(collector); err != nil {
		var alreadyRegistered prometheus.AlreadyRegisteredError
		if errors.As(err, &alreadyRegistered) {
			if existing, ok := alreadyRegistered.ExistingCollector.(prometheus.Histogram); ok {
				return existing
			}
			log.Printf("filterlist metrics: collector type mismatch for histogram reuse: %v", err)
			return collector
		}
		log.Printf("filterlist metrics: failed to register histogram: %v", err)
	}

	return collector
}

// registerHistogramVec registers a HistogramVec or reuses an existing one with the same descriptor.
func registerHistogramVec(reg prometheus.Registerer, collector *prometheus.HistogramVec) *prometheus.HistogramVec {
	if err := reg.Register(collector); err != nil {
		var alreadyRegistered prometheus.AlreadyRegisteredError
		if errors.As(err, &alreadyRegistered) {
			if existing, ok := alreadyRegistered.ExistingCollector.(*prometheus.HistogramVec); ok {
				return existing
			}
			log.Printf("filterlist metrics: collector type mismatch for histogram vector reuse: %v", err)
			return collector
		}
		log.Printf("filterlist metrics: failed to register histogram vector: %v", err)
	}

	return collector
}
