package filterlist_test

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/TomTonic/filterlist/pkg/automaton"
	"github.com/TomTonic/filterlist/pkg/matcher"
	"github.com/TomTonic/rtcompare"
)

var benchmarkMatchCount int

// BenchmarkSequenceMapVsDFA compiles the realistic denylist rule set and then
// benchmarks matching a deterministic pseudo-random sequence of domains drawn
// from the provided Cloudflare CSV. It reports separate benchmark runs for the
// hybrid suffix-map+DFA matcher and for a pure-automaton matcher.
//
// Sequence sizes can be controlled with the environment variable
// BENCH_SEQ_SIZE (single integer). If unset, the benchmark runs a small set of
// sizes to explore scaling.
func BenchmarkSequenceMapVsDFA(b *testing.B) {
	// Locate CSV in repository testdata directory.
	_, filename, _, _ := runtime.Caller(0)
	csvPath := filepath.Join(filepath.Dir(filename), "testdata", "cloudflare-radar_top-1000000-domains_20260327-20260403.csv")

	domains := loadDomainsFromCSV(b, csvPath)

	// Allow overriding a single sequence size via env var.
	sizes := []int{50_000, 100_000, 200_000}
	if v := os.Getenv("BENCH_SEQ_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			sizes = []int{n}
		}
	}

	// Compile hybrid matcher (suffix map + DFA) and measure time.
	b.Logf("compiling hybrid matcher (rules -> suffixmap + dfa)")
	t0 := time.Now()
	rules := loadRealisticDenylistRules(b)
	hybrid, err := matcher.CompileRules(rules, matcher.CompileOptions{MaxStates: realisticBenchmarkMaxStates})
	if err != nil {
		b.Fatalf("CompileRules error: %v", err)
	}
	compileHybrid := time.Since(t0)

	// Compile pure automaton (force all patterns through automaton) and measure.
	b.Logf("compiling pure automaton (all patterns through automaton)")
	t1 := time.Now()
	patterns := loadRealisticDenylistPatterns(b)
	pure, err := automaton.Compile(patterns, automaton.CompileOptions{MaxStates: realisticBenchmarkMaxStates})
	if err != nil {
		b.Fatalf("automaton.Compile error: %v", err)
	}
	compilePure := time.Since(t1)
	totalCompile := compileHybrid + compilePure

	b.Logf("compile: hybrid=%s pure=%s", compileHybrid, compilePure)

	timesHybrid := make([]float64, 0, 1_000_000)
	timesPure := make([]float64, 0, 1_000_000)
	//oldGCPercent := debug.SetGCPercent(-1) // Disable GC during benchmarking to avoid noise; we'll trigger manually between runs.
	// defer debug.SetGCPercent(oldGCPercent)

	for _, seqLen := range sizes {
		timesHybrid = timesHybrid[:0]
		timesPure = timesPure[:0]

		hybridHits := 0
		hybridMatches := 0
		pureHits := 0
		pureMatches := 0
		seed := uint64(seqLen*123456789 + 11) // Seed based on length for reproducibility across runs.

		runtime.GC()
		runtime.GC()
		runtime.GC()

		// Benchmark hybrid matcher over the deterministic sequence.
		b.Run(fmt.Sprintf("seq=%d/hybrid", seqLen), func(b *testing.B) {
			b.ReportAllocs()
			dprng := rtcompare.NewDPRNG(seed) // DPRNG is deterministic in sequence and has constant memory and execution time
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				t1 := rtcompare.SampleTime()
				for range seqLen {
					idx := dprng.UInt32N(uint32(len(domains)))
					d := domains[int(idx)]
					if hit, _ := hybrid.Match(d); hit {
						hybridHits++
					}
					hybridMatches++
				}
				t2 := rtcompare.SampleTime()
				timesHybrid = append(timesHybrid, float64(rtcompare.DiffTimeStamps(t1, t2))/float64(seqLen))
			}
		})

		runtime.GC()
		runtime.GC()
		runtime.GC()

		// Benchmark pure DFA matcher over the deterministic sequence.
		b.Run(fmt.Sprintf("seq=%d/pure", seqLen), func(b *testing.B) {
			b.ReportAllocs()
			dprng := rtcompare.NewDPRNG(seed) // DPRNG is deterministic in sequence and has constant memory and execution time
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				t1 := rtcompare.SampleTime()
				for range seqLen {
					idx := dprng.UInt32N(uint32(len(domains)))
					d := domains[int(idx)]
					if hit, _ := pure.Match(d); hit {
						pureHits++
					}
					pureMatches++
				}
				t2 := rtcompare.SampleTime()
				timesPure = append(timesPure, float64(rtcompare.DiffTimeStamps(t1, t2))/float64(seqLen))
			}
		})

		runtime.GC()

		hybridMedian := rtcompare.QuickMedian(timesHybrid)
		pureMedian := rtcompare.QuickMedian(timesPure)

		fmt.Printf(
			"\nBenchmarkSequenceMapVsDFA seq = %d, hybrid: %d iterations, pure: %d iterations\n",
			seqLen,
			hybridMatches,
			pureMatches,
		)

		// Combined measurement: report compile cost and per-domain lookup cost.
		fmt.Printf(
			"compile_hybrid = %s\ncompile_pure   = %s\ntotal_compile  = %s\n",
			compileHybrid,
			compilePure,
			totalCompile,
		)

		fmt.Printf(
			"hybrid: median_per_domain = %.2fns\npure:   median_per_domain = %.2fns\n\n",
			hybridMedian,
			pureMedian,
		)
	}
}

// loadDomainsFromCSV reads the first column from a CSV and returns a slice of
// domain names. It skips an initial header row if present.
func loadDomainsFromCSV(tb testing.TB, path string) []string {
	tb.Helper()
	f, err := os.Open(path)
	if err != nil {
		tb.Skipf("CSV file not found (%s): %v", path, err)
	}
	defer f.Close()

	// Use the csv.Reader for robust parsing; stream rows to avoid large
	// temporary allocations for huge files.
	r := csv.NewReader(bufio.NewReader(f))
	var domains []string
	first := true
	for {
		rec, err := r.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			tb.Fatalf("error reading csv: %v", err)
		}
		if len(rec) == 0 {
			continue
		}
		val := strings.TrimSpace(rec[0])
		if val == "" {
			continue
		}
		// Skip header line if it looks like a header on the first row.
		if first {
			first = false
			low := strings.ToLower(val)
			if strings.Contains(low, "domain") || strings.Contains(low, "rank") {
				continue
			}
		}
		domains = append(domains, val)
	}

	if len(domains) == 0 {
		tb.Skipf("no domains found in CSV %s", path)
	}
	return domains
}
