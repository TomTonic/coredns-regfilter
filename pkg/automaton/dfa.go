package automaton

import (
	"runtime"
	"sync"
)

// byteIndex maps ASCII byte values to alphabet indices for fast backward
// iteration in [DFA.MatchDomain]. Using a 256-byte lookup table avoids the
// switch ladder and rune conversion overhead of [runeToIndex] in the hot loop.
var byteIndex [256]byte

func init() {
	for i := range byteIndex {
		byteIndex[i] = noAlphabetIndex
	}
	for r := byte('a'); r <= byte('z'); r++ {
		byteIndex[r] = r - 'a'
	}
	for r := byte('0'); r <= byte('9'); r++ {
		byteIndex[r] = 26 + r - '0'
	}
	byteIndex['-'] = 36
	byteIndex['.'] = 37
}

// DFAState is one state in the compiled deterministic finite automaton.
//
// Transitions are stored in a fixed-size array indexed by [runeToIndex],
// with nil entries indicating no transition (dead end). Each non-nil entry
// is a direct pointer to the successor [DFAState] — no map lookups, no index
// indirection, just a single pointer chase per input character at match time.
//
// # Memory Layout
//
// On 64-bit systems each DFAState is 38 pointers (304 B) for Trans, one bool
// (Accept), and a slice header (RuleIDs). Keeping Trans as a fixed array
// rather than a map or sparse structure ensures that the CPU prefetcher can
// stride through transition lookups predictably. All states are allocated in
// a single contiguous []DFAState slice inside [DFA], further improving spatial
// locality.
type DFAState struct {
	Trans   [AlphabetSize]*DFAState
	Accept  bool
	RuleIDs []uint32 // which filter rules led to this accept state
}

// DFA is a compiled deterministic finite automaton for domain name matching.
//
// States reside in a single contiguous slice for cache locality, and
// transitions are direct pointers between elements of that slice — no map
// lookups or index indirection at match time.
//
// Create a DFA with [Compile]; query it with [DFA.Match].
type DFA struct {
	start  *DFAState
	states []DFAState
}

// Match checks whether input is accepted by the compiled DFA and returns the
// matching rule IDs.
//
// The input parameter should be a lowercase DNS domain name. Match traverses
// the DFA one rune at a time in O(n) where n = len(input). It returns false
// immediately when a rune falls outside the DNS alphabet or leads to a dead
// end (nil transition pointer).
//
// A nil or empty DFA always returns (false, nil).
func (d *DFA) Match(input string) (matched bool, ruleIDs []uint32) {
	if d == nil || d.start == nil {
		return false, nil
	}
	s := d.start
	for _, r := range input {
		idx := runeToIndex(r)
		if idx == noAlphabetIndex {
			return false, nil
		}
		s = s.Trans[idx]
		if s == nil {
			return false, nil
		}
	}
	if s.Accept {
		return true, s.RuleIDs
	}
	return false, nil
}

// MatchDomain checks whether the DFA — compiled from reversed patterns —
// matches the given domain name with ||domain^ anchoring semantics.
//
// Instead of reversing the input string (which would allocate), MatchDomain
// walks the input bytes from right to left, feeding them into the DFA one
// character at a time. This is equivalent to feeding the reversed input in
// forward order.
//
// A match is recorded whenever the DFA reaches an accepting state at a domain
// boundary, defined as:
//   - the beginning of the input (i == 0, meaning the entire name matched), or
//   - immediately after a '.' label separator (input[i-1] == '.').
//
// This boundary logic replaces the old approach of generating synthetic
// "*.<pattern>" variants for every rule, which caused exponential DFA state
// explosion when the original pattern already contained wildcards.
//
// The input parameter should be a lowercase DNS domain name without trailing
// dot. A nil or empty DFA always returns (false, nil).
//
// Typical callers are [matcher.Matcher.Match] and other high-level entry
// points that compile reversed patterns via [Compile]. For raw exact-match
// semantics on non-reversed patterns, use [DFA.Match] instead.
func (d *DFA) MatchDomain(input string) (matched bool, ruleIDs []uint32) {
	if d == nil || d.start == nil {
		return false, nil
	}

	s := d.start
	n := len(input)

	if n == 0 {
		if s.Accept {
			return true, s.RuleIDs
		}
		return false, nil
	}

	// firstIDs tracks the first boundary match. As long as only one boundary
	// accepts, we return the DFA state's own RuleIDs slice directly —
	// identical to what Match does — avoiding any allocation.
	var firstIDs []uint32

	for i := n - 1; i >= 0; i-- {
		idx := byteIndex[input[i]]
		if idx == noAlphabetIndex {
			break
		}
		next := s.Trans[idx]
		if next == nil {
			break
		}
		s = next

		if s.Accept && (i == 0 || input[i-1] == '.') {
			switch {
			case !matched:
				matched = true
				firstIDs = s.RuleIDs
			case ruleIDs == nil:
				// Second boundary hit — allocate and merge both sets.
				ruleIDs = make([]uint32, 0, len(firstIDs)+len(s.RuleIDs))
				ruleIDs = append(ruleIDs, firstIDs...)
				ruleIDs = appendUniqueIDs(ruleIDs, s.RuleIDs)
			default:
				ruleIDs = appendUniqueIDs(ruleIDs, s.RuleIDs)
			}
		}
	}

	if ruleIDs != nil {
		return matched, ruleIDs
	}
	return matched, firstIDs
}

// appendUniqueIDs appends rule IDs from src to dst, skipping duplicates.
// The expected cardinality is tiny (1–3 IDs per match), so a linear scan
// is faster than a hash set.
func appendUniqueIDs(dst, src []uint32) []uint32 {
	for _, id := range src {
		dup := false
		for _, existing := range dst {
			if existing == id {
				dup = true
				break
			}
		}
		if !dup {
			dst = append(dst, id)
		}
	}
	return dst
}

// StateCount reports how many DFA states are currently allocated.
//
// Returns 0 for a nil receiver or an empty DFA. Callers typically use this
// for metrics, diagnostics, and capacity planning.
func (d *DFA) StateCount() int {
	if d == nil {
		return 0
	}
	return len(d.states)
}

// toDFA converts an intermediate DFA (used during compilation) to the
// exported pointer-based [DFA].
//
// The conversion allocates all [DFAState] values in a single contiguous slice
// and then patches transition entries to point directly into that slice.
// For large state counts the patching work is distributed across goroutines,
// where each goroutine processes a disjoint chunk of the state slice.
func (md *intermediateDFA) toDFA() *DFA {
	n := md.stateCount()
	d := &DFA{states: make([]DFAState, n)}

	if n == 0 {
		return d
	}

	numWorkers := runtime.GOMAXPROCS(0)

	if n >= numWorkers*64 && numWorkers > 1 {
		chunkSize := (n + numWorkers - 1) / numWorkers
		var wg sync.WaitGroup
		for w := range numWorkers {
			lo := w * chunkSize
			if lo >= n {
				break
			}
			hi := min(lo+chunkSize, n)
			wg.Add(1)
			go func(lo, hi int) {
				defer wg.Done()
				for i := lo; i < hi; i++ {
					ds := &d.states[i]
					ds.Accept = md.accept[i]
					ds.RuleIDs = md.ruleIDs[i]
					trans := md.stateTrans(i)
					for idx, target := range trans {
						if target != noTransitionState {
							ds.Trans[idx] = &d.states[target]
						}
					}
				}
			}(lo, hi)
		}
		wg.Wait()
	} else {
		for i := range n {
			d.states[i].Accept = md.accept[i]
			d.states[i].RuleIDs = md.ruleIDs[i]
		}
		for i := range n {
			trans := md.stateTrans(i)
			for idx, target := range trans {
				if target != noTransitionState {
					d.states[i].Trans[idx] = &d.states[target]
				}
			}
		}
	}

	d.start = &d.states[md.start]
	return d
}
