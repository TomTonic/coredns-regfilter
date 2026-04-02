// Package automaton compiles domain filter patterns into a cache-optimized,
// array-based deterministic finite automaton (DFA) with rule attribution.
//
// The compilation pipeline is: Thompson NFA → subset construction → Hopcroft
// minimization → contiguous-slice DFA with direct-pointer transitions.
//
// The supported pattern language is intentionally small:
//   - Literal characters: a-z, 0-9, '-', '.'
//   - Wildcard: '*' matches zero or more DNS characters
//   - Patterns are implicitly anchored (full match)
//
// Example usage:
//
//	dfa, err := automaton.Compile(patterns, automaton.CompileOptions{})
//	matched, ruleIDs := dfa.Match("ads.example.com")
package automaton

import (
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
	"slices"
	"sort"
	"strings"
	"time"
)

// Logger receives progress messages during DFA compilation.
// The watcher and CoreDNS plugin pass their logger here so users
// see what is happening during potentially long compilations.
type Logger interface {
	Infof(format string, args ...interface{})
}

func nopLogf(string, ...interface{}) {}

// AlphabetSize is the number of characters in the DNS alphabet (a-z, 0-9, '-', '.').
const AlphabetSize = 38

// dnsAlphabet lists all valid DNS characters in index order.
var dnsAlphabet [AlphabetSize]rune

func init() {
	for i := range AlphabetSize {
		dnsAlphabet[i] = indexToRune(i)
	}
}

// runeToIndex maps r to its DFA transition index.
//
// Returns a byte in [0, AlphabetSize) for valid DNS characters (a-z, 0-9,
// '-', '.'), or noAlphabetIndex (0xFF) when r is outside that alphabet.
// Used on hot matching paths and during NFA construction.
func runeToIndex(r rune) byte {
	switch {
	case r >= 'a' && r <= 'z':
		return byte(r - 'a') //nolint:gosec // r∈['a','z'], r-'a'∈[0,25] fits byte
	case r >= '0' && r <= '9':
		return 26 + byte(r-'0') //nolint:gosec // r∈['0','9'], 26+r-'0'∈[26,35] fits byte
	case r == '-':
		return 36
	case r == '.':
		return 37
	default:
		return noAlphabetIndex
	}
}

// indexToRune maps i back to the DNS character used at that transition slot.
//
// The i parameter must be in the inclusive range [0, AlphabetSize). The return
// value is the DNS rune stored at that index, or -1 when i is outside the
// supported alphabet. Mainly useful for diagnostics such as DOT output.
func indexToRune(i int) rune {
	switch {
	case i >= 0 && i <= 25:
		return rune('a' + i)
	case i >= 26 && i <= 35:
		return rune('0' + i - 26)
	case i == 36:
		return '-'
	case i == 37:
		return '.'
	default:
		return -1
	}
}

// ---- NFA ----

const epsilon rune = 0 // epsilon transitions use rune 0
const noTransitionState uint32 = math.MaxUint32
const noAlphabetIndex byte = 0xFF

const (
	nfaFlagHasLiteral uint8 = 1 << iota
	nfaFlagHasAnyDNS
	nfaFlagAccept
)

// nfaState is one node in the Thompson NFA with labeled transitions.
//
// Thompson construction in this package produces at most one literal outgoing
// edge per state plus optional epsilon fan-out and an optional anyDNS loop.
// Storing those paths directly is markedly smaller and more cache-friendly
// than allocating a general-purpose map for every state.
type nfaState struct {
	literalTo    uint32
	anyDNSTo     uint32
	literalIndex byte
	flags        byte
	epsilon      []uint32
	ruleIDs      []uint32
}

func (s *nfaState) hasLiteralTransition() bool {
	return s.flags&nfaFlagHasLiteral != 0
}

func (s *nfaState) hasAnyDNSTransition() bool {
	return s.flags&nfaFlagHasAnyDNS != 0
}

func (s *nfaState) isAccept() bool {
	return s.flags&nfaFlagAccept != 0
}

func (s *nfaState) setAccept(accept bool) {
	if accept {
		s.flags |= nfaFlagAccept
		return
	}
	s.flags &^= nfaFlagAccept
}

// nfa holds the complete non-deterministic finite automaton before subset construction.
type nfa struct {
	states []nfaState
	start  int
}

// closureScratch reuses dense visitation state for repeated epsilon closures.
// NFA state IDs are contiguous slice indices, so indexed marks fit better than
// a generic hash set during subset construction.
type closureScratch struct {
	marks  []uint32
	stamp  uint32
	stack  []int
	result []int
	keyBuf []byte
}

// newClosureScratch preallocates reusable state for repeated epsilon closures.
func newClosureScratch(stateCount int) *closureScratch {
	return &closureScratch{marks: make([]uint32, stateCount)}
}

// addState appends a fresh state and returns its ID.
func (n *nfa) addState() int {
	id := len(n.states)
	n.states = append(n.states, nfaState{
		literalTo: noTransitionState,
		anyDNSTo:  noTransitionState,
	})
	return id
}

// addTrans records a labeled transition from one NFA state to another.
func (n *nfa) addTrans(from int, r rune, to int) error {
	state := &n.states[from]
	if r == epsilon {
		state.epsilon = append(state.epsilon, uint32(to)) //nolint:gosec // to=addState()≥0, fits uint32
		return nil
	}

	idx := runeToIndex(r)
	if idx == noAlphabetIndex {
		return fmt.Errorf("unsupported character %q in pattern", r)
	}

	state.literalIndex = idx
	state.literalTo = uint32(to) //nolint:gosec // to=addState()≥0, fits uint32
	state.flags |= nfaFlagHasLiteral
	return nil
}

// addAnyDNSTrans records a transition taken for any supported DNS character.
func (n *nfa) addAnyDNSTrans(from int, to int) {
	n.states[from].anyDNSTo = uint32(to) //nolint:gosec // to=addState()≥0, fits uint32
	n.states[from].flags |= nfaFlagHasAnyDNS
}

// buildPatternNFA constructs a Thompson NFA for a single pattern.
// Pattern language: literal chars, '.' literal, '*' = zero-or-more DNS chars.
func buildPatternNFA(pattern string, ruleID uint32) (*nfa, error) {
	n := &nfa{states: make([]nfaState, 0, len(pattern)+2)}
	start := n.addState()
	n.start = start

	current := start
	for _, r := range pattern {
		switch {
		case r == '*':
			// Wildcard: self-loop on the DNS character class.
			loopState := n.addState()
			if err := n.addTrans(current, epsilon, loopState); err != nil {
				return nil, err
			}
			n.addAnyDNSTrans(loopState, loopState)
			current = loopState
		case runeToIndex(r) != noAlphabetIndex:
			next := n.addState()
			if err := n.addTrans(current, r, next); err != nil {
				return nil, err
			}
			current = next
		default:
			return nil, fmt.Errorf("unsupported character %q in pattern", r)
		}
	}

	// Mark final state as accept
	n.states[current].setAccept(true)
	n.states[current].ruleIDs = []uint32{ruleID}
	return n, nil
}

// combineNFAs merges multiple NFAs into one with a new start state connected
// via epsilon transitions.
func combineNFAs(nfas []*nfa) (*nfa, error) {
	totalStates := 1
	for _, sub := range nfas {
		totalStates += len(sub.states)
	}
	combined := &nfa{states: make([]nfaState, 0, totalStates)}
	newStart := combined.addState()
	combined.start = newStart

	for _, sub := range nfas {
		offset := uint32(len(combined.states)) //nolint:gosec // len() is always ≥0
		// Copy all states
		for _, s := range sub.states {
			newID := combined.addState()
			combined.states[newID].setAccept(s.isAccept())
			combined.states[newID].ruleIDs = append([]uint32(nil), s.ruleIDs...)
		}
		// Rewrite transitions with offset
		for i, s := range sub.states {
			iOff := i + int(offset)
			for _, t := range s.epsilon {
				if err := combined.addTrans(iOff, epsilon, int(t+offset)); err != nil {
					return nil, err
				}
			}
			if s.hasLiteralTransition() {
				combined.states[iOff].literalIndex = s.literalIndex
				combined.states[iOff].literalTo = s.literalTo + offset
				combined.states[iOff].flags |= nfaFlagHasLiteral
			}
			if s.hasAnyDNSTransition() {
				combined.states[iOff].anyDNSTo = s.anyDNSTo + offset
				combined.states[iOff].flags |= nfaFlagHasAnyDNS
			}
		}
		// Epsilon from new start to sub's start
		if err := combined.addTrans(newStart, epsilon, sub.start+int(offset)); err != nil {
			return nil, err
		}
	}
	return combined, nil
}

// epsilonClosure computes the set of states reachable from the given set via
// epsilon transitions.
func epsilonClosure(cs *closureScratch, n *nfa, states []int) []int {
	cs.stamp++
	if cs.stamp == 0 {
		clear(cs.marks)
		cs.stamp = 1
	}

	stack := cs.stack[:0]
	result := cs.result[:0]

	for _, s := range states {
		if cs.marks[s] == cs.stamp {
			continue
		}
		cs.marks[s] = cs.stamp
		stack = append(stack, s)
	}

	for len(stack) > 0 {
		s := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		result = append(result, s)
		for _, t := range n.states[s].epsilon {
			if cs.marks[t] == cs.stamp {
				continue
			}
			cs.marks[t] = cs.stamp
			stack = append(stack, int(t))
		}
	}

	slices.Sort(result)
	cs.stack = stack
	cs.result = result
	return result
}

// ---- Intermediate DFA (used only during construction and minimization) ----

// intermediateDFAState is one state in the intermediate DFA.
//
// Transitions are stored in a compact, fixed-size array indexed by the
// DNS alphabet position (runeToIndex) to reduce heap churn during subset
// construction and Hopcroft minimization.
type intermediateDFAState struct {
	trans   [AlphabetSize]uint32
	accept  bool
	ruleIDs []uint32
}

// intermediateDFA is the temporary DFA used during subset construction and
// Hopcroft minimization before conversion to the exported pointer-based DFA.
type intermediateDFA struct {
	start  int
	states []intermediateDFAState
}

type subsetWorkItem struct {
	id     uint32
	states []int
}

type subsetTransitionScratch struct {
	activeLiteralMask uint64
	literalTargets    [AlphabetSize][]int
	wildcardTargets   []int
	moved             []int
}

func (s *subsetTransitionScratch) reset() {
	mask := s.activeLiteralMask
	for mask != 0 {
		idx := bits.TrailingZeros64(mask)
		s.literalTargets[idx] = s.literalTargets[idx][:0]
		mask &^= uint64(1) << idx
	}
	s.activeLiteralMask = 0
	s.wildcardTargets = s.wildcardTargets[:0]
	s.moved = s.moved[:0]
}

func (s *subsetTransitionScratch) collect(n *nfa, states []int) {
	s.reset()
	for _, stateID := range states {
		state := &n.states[stateID]
		if state.hasLiteralTransition() {
			idx := int(state.literalIndex)
			s.activeLiteralMask |= uint64(1) << idx
			s.literalTargets[idx] = append(s.literalTargets[idx], int(state.literalTo))
		}
		if state.hasAnyDNSTransition() {
			s.wildcardTargets = append(s.wildcardTargets, int(state.anyDNSTo))
		}
	}
}

func newIntermediateDFAState(accept bool, ruleIDs []uint32) intermediateDFAState {
	s := intermediateDFAState{
		accept:  accept,
		ruleIDs: ruleIDs,
	}
	for i := range s.trans {
		s.trans[i] = noTransitionState
	}
	return s
}

// ---- Exported DFA (array-based, cache-optimized) ----

// DFAState represents a single state in the deterministic finite automaton.
// Transitions are stored in a fixed-size array indexed by [RuneToIndex],
// with nil entries indicating no transition (dead end). Each non-nil entry
// is a direct pointer to the successor state — no map lookups or index
// indirection at match time.
type DFAState struct {
	Trans   [AlphabetSize]*DFAState
	Accept  bool
	RuleIDs []uint32 // which rules led to this accept state
}

// DFA is an array-based deterministic finite automaton compiled from domain
// filter patterns. States reside in a single contiguous slice for cache
// locality and transitions are direct pointers — no map lookups or index
// indirection at match time.
type DFA struct {
	start  *DFAState
	states []DFAState
}

// CompileOptions controls the compilation process.
type CompileOptions struct {
	// MaxStates limits the number of DFA states. 0 means no limit.
	MaxStates int
	// Minimize enables Hopcroft minimization (default: true via zero value handling).
	Minimize *bool
	// CompileTimeout is the maximum time allowed for compilation.
	CompileTimeout time.Duration
	// Logger receives progress messages during compilation. May be nil.
	Logger Logger
}

// shouldMinimize returns whether Hopcroft minimization is enabled for these options.
func shouldMinimize(opts CompileOptions) bool {
	if opts.Minimize == nil {
		return true // default to minimize
	}
	return *opts.Minimize
}

// Pattern pairs a canonical filter pattern string with its rule ID.
type Pattern struct {
	Expr   string // canonical pattern (lowercase DNS chars and '*')
	RuleID uint32 // caller-assigned identifier for match attribution
}

// Compile compiles patterns into a minimized DFA ready for repeated Match
// calls.
//
// Each Pattern carries a lowercase expression string from the supported
// alphabet (a-z, 0-9, '-', '.', '*') and a caller-assigned rule ID that is
// preserved in accept states for match attribution. The opts parameter
// controls state limits, Hopcroft minimization, an optional compile timeout,
// and a progress logger.
//
// On failure Compile returns an error describing invalid patterns, timeout
// exhaustion, or MaxStates violations.
func Compile(patterns []Pattern, opts CompileOptions) (*DFA, error) {
	logf := nopLogf
	if opts.Logger != nil {
		logf = opts.Logger.Infof
	}

	if len(patterns) == 0 {
		logf("automaton: 0 patterns, nothing to compile")
		return &DFA{}, nil
	}

	started := time.Now()
	deadline := time.Time{}
	if opts.CompileTimeout > 0 {
		deadline = time.Now().Add(opts.CompileTimeout)
	}

	// Build per-pattern NFAs.
	logf("automaton: building %d NFAs...", len(patterns))
	nfaStart := time.Now()
	nfas := make([]*nfa, 0, len(patterns))
	for i, p := range patterns {
		if !deadline.IsZero() && time.Now().After(deadline) {
			return nil, fmt.Errorf("automaton: compile timeout after %d/%d patterns", i, len(patterns))
		}
		expr := strings.ToLower(p.Expr)
		n, err := buildPatternNFA(expr, p.RuleID)
		if err != nil {
			return nil, fmt.Errorf("automaton: pattern %d: %w", i, err)
		}
		nfas = append(nfas, n)
	}
	logf("automaton: NFA build: %v", time.Since(nfaStart))

	// Combine into single NFA.
	combineStart := time.Now()
	combined, err := combineNFAs(nfas)
	if err != nil {
		return nil, err
	}
	logf("automaton: NFA combine: %v (%d NFA states)", time.Since(combineStart), len(combined.states))

	// Subset construction: NFA → map-based DFA.
	logf("automaton: starting subset construction...")
	subsetStart := time.Now()
	md, err := subsetConstruction(combined, opts.MaxStates, deadline)
	if err != nil {
		return nil, err
	}
	logf("automaton: subset construction: %v (%d DFA states)", time.Since(subsetStart), len(md.states))

	// Hopcroft minimization.
	if shouldMinimize(opts) {
		logf("automaton: starting Hopcroft minimization (%d states)...", len(md.states))
		hopcroftStart := time.Now()
		beforeStates := len(md.states)
		md = hopcroftMinimize(md)
		logf("automaton: Hopcroft minimization: %v (%d → %d states)",
			time.Since(hopcroftStart), beforeStates, len(md.states))
	}

	// Convert to array/pointer-based DFA.
	dfa := md.toDFA()
	logf("automaton: compiled %d patterns in %v (%d DFA states)",
		len(patterns), time.Since(started), dfa.StateCount())
	return dfa, nil
}

// toDFA converts an internal intermediate DFA to the exported pointer-based DFA.
func (md *intermediateDFA) toDFA() *DFA {
	d := &DFA{states: make([]DFAState, len(md.states))}

	for i := range md.states {
		ms := &md.states[i]
		d.states[i].Accept = ms.accept
		d.states[i].RuleIDs = ms.ruleIDs
	}

	for i := range md.states {
		ms := &md.states[i]
		for idx, target := range ms.trans {
			if target != noTransitionState {
				d.states[i].Trans[idx] = &d.states[target]
			}
		}
	}

	d.start = &d.states[md.start]
	return d
}

// subsetBuilder holds the mutable state shared between subsetConstruction and
// its getOrCreateState method, avoiding closure captures.
type subsetBuilder struct {
	nfa         *nfa
	md          *intermediateDFA
	closures    *closureScratch
	stateMap    map[string]uint32
	worklist    []subsetWorkItem
	transitions subsetTransitionScratch
	maxStates   int
}

// getOrCreateState returns the uint32 DFA-state ID for the epsilon closure of
// source, creating a new state when no matching closure exists yet.
//
// The source parameter is a list of NFA state IDs. Returns an error when the
// set-key encoding fails or MaxStates would be exceeded.
func (b *subsetBuilder) getOrCreateState(source []int) (uint32, error) {
	closure := epsilonClosure(b.closures, b.nfa, source)
	key, err := makeSetKey(&b.closures.keyBuf, closure)
	if err != nil {
		return 0, err
	}
	if existingID, exists := b.stateMap[key]; exists {
		return existingID, nil
	}
	if b.maxStates > 0 && len(b.md.states) >= b.maxStates {
		return 0, fmt.Errorf("automaton: exceeded MaxStates limit (%d)", b.maxStates)
	}
	newID := uint32(len(b.md.states)) //nolint:gosec // bounded by maxStates, len() is always ≥0
	b.stateMap[key] = newID
	accept, ruleIDs := computeAccept(b.nfa, closure)
	b.md.states = append(b.md.states, newIntermediateDFAState(accept, ruleIDs))
	b.worklist = append(b.worklist, subsetWorkItem{id: newID, states: slices.Clone(closure)})
	return newID, nil
}

// subsetConstruction converts an NFA to an intermediate DFA using the classic algorithm.
func subsetConstruction(n *nfa, maxStates int, deadline time.Time) (*intermediateDFA, error) {
	md := &intermediateDFA{states: make([]intermediateDFAState, 0, 1024)}
	b := &subsetBuilder{
		nfa:       n,
		md:        md,
		closures:  newClosureScratch(len(n.states)),
		stateMap:  make(map[string]uint32, 1024),
		maxStates: maxStates,
	}

	startResult := epsilonClosure(b.closures, n, []int{n.start})
	startKey, err := makeSetKey(&b.closures.keyBuf, startResult)
	if err != nil {
		return nil, err
	}
	b.stateMap[startKey] = 0
	md.start = 0

	accept, ruleIDs := computeAccept(n, startResult)
	md.states = append(md.states, newIntermediateDFAState(accept, ruleIDs))
	b.worklist = append(b.worklist, subsetWorkItem{id: 0, states: slices.Clone(startResult)})

	for len(b.worklist) > 0 {
		if !deadline.IsZero() && time.Now().After(deadline) {
			return nil, errors.New("automaton: subset construction timeout")
		}

		currentItem := b.worklist[0]
		b.worklist = b.worklist[1:]
		current := currentItem.states
		currentID := currentItem.id
		b.transitions.collect(n, current)

		if len(b.transitions.wildcardTargets) > 0 {
			wildcardID, wErr := b.getOrCreateState(b.transitions.wildcardTargets)
			if wErr != nil {
				return nil, wErr
			}
			for idx := range AlphabetSize {
				md.states[currentID].trans[idx] = wildcardID
			}
		}

		mask := b.transitions.activeLiteralMask
		for mask != 0 {
			idx := bits.TrailingZeros64(mask)
			mask &^= uint64(1) << idx

			literalTargets := b.transitions.literalTargets[idx]
			if len(b.transitions.wildcardTargets) == 0 {
				stateID, stateErr := b.getOrCreateState(literalTargets)
				if stateErr != nil {
					return nil, stateErr
				}
				md.states[currentID].trans[idx] = stateID
				continue
			}

			moved := b.transitions.moved[:0]
			moved = append(moved, b.transitions.wildcardTargets...)
			moved = append(moved, literalTargets...)
			b.transitions.moved = moved[:0]

			stateID, stateErr := b.getOrCreateState(moved)
			if stateErr != nil {
				return nil, stateErr
			}
			md.states[currentID].trans[idx] = stateID
		}
	}

	return md, nil
}

// computeAccept derives the accept flag and merged rule IDs for a DFA state set.
func computeAccept(n *nfa, stateSet []int) (accept bool, ruleIDs []uint32) {
	for _, s := range stateSet {
		if n.states[s].isAccept() {
			accept = true
			ruleIDs = append(ruleIDs, n.states[s].ruleIDs...)
		}
	}
	if len(ruleIDs) > 1 {
		slices.Sort(ruleIDs)
		ruleIDs = slices.Compact(ruleIDs)
	}
	return accept, ruleIDs
}

// makeSetKey serializes a sorted state set into a deterministic binary key for
// the state map. Each state ID occupies a fixed four-byte slot so concatenated
// keys remain unambiguous without decimal formatting or variable-length codecs.
func makeSetKey(buf *[]byte, states []int) (string, error) {
	b := (*buf)[:0]
	for _, s := range states {
		var err error
		b, err = appendFixedUint32(b, s)
		if err != nil {
			return "", err
		}
	}
	*buf = b
	return string(b), nil
}

func appendFixedUint32(buf []byte, value int) ([]byte, error) {
	if value < 0 || value > math.MaxUint32 {
		return nil, fmt.Errorf("automaton: state id %d out of uint32 range", value)
	}

	return append(buf,
		byte(value&0xff),
		byte(value>>8&0xff),
		byte(value>>16&0xff),
		byte(value>>24&0xff),
	), nil
}

// checkedStateID32 and checkedAlphabetIndex8 have been removed: state IDs are
// now stored as uint32 throughout, and runeToIndex returns byte directly.

// ---- Hopcroft Minimization ----

type ruleIDsFingerprint struct {
	hash   uint64
	length int
}

type acceptPartitionBucket struct {
	ruleIDs []uint32
	states  []int
}

type transitionSignature [AlphabetSize]uint32

var noTransSig transitionSignature

func init() {
	for i := range noTransSig {
		noTransSig[i] = noTransitionState
	}
}

// hopcroftMinimize merges equivalent states to produce a minimal DFA.
func hopcroftMinimize(md *intermediateDFA) *intermediateDFA {
	n := len(md.states)
	if n <= 1 {
		return md
	}

	// Initial partition: accept states vs non-accept states
	// Further split accept states by ruleID sets for correct attribution.
	partitions := initialPartitions(md)

	// stateToPartition: state -> partition index
	stateToPartition := make([]uint32, n)
	updateMapping := func() {
		for pi, p := range partitions {
			p32 := uint32(pi) //nolint:gosec // pi is a range index, always ≥0
			for _, s := range p {
				stateToPartition[s] = p32
			}
		}
	}
	updateMapping()

	// Hopcroft refinement
	changed := true
	for changed {
		changed = false
		newPartitions := make([][]int, 0, len(partitions)+len(partitions)/4)
		for _, p := range partitions {
			if len(p) <= 1 {
				newPartitions = append(newPartitions, p)
				continue
			}
			split := splitPartition(md, p, stateToPartition)
			if len(split) > 1 {
				changed = true
			}
			newPartitions = append(newPartitions, split...)
		}
		partitions = newPartitions
		updateMapping()
	}

	// Build minimized intermediateDFA.
	minMD := &intermediateDFA{}
	minMD.states = make([]intermediateDFAState, len(partitions))
	for pi, p := range partitions {
		rep := p[0]
		minMD.states[pi] = newIntermediateDFAState(md.states[rep].accept, md.states[rep].ruleIDs)
		for idx, target := range md.states[rep].trans {
			if target != noTransitionState {
				minMD.states[pi].trans[idx] = stateToPartition[target]
			}
		}
	}
	minMD.start = int(stateToPartition[md.start])

	return minMD
}

// initialPartitions separates non-accepting states from accepting states and
// keeps distinct rule-ID sets in different starting buckets.
func initialPartitions(md *intermediateDFA) [][]int {
	nonAccept := make([]int, 0, len(md.states))
	bucketIndexByFingerprint := make(map[ruleIDsFingerprint][]int)
	acceptBuckets := make([]acceptPartitionBucket, 0)

	for i := range md.states {
		s := &md.states[i]
		if !s.accept {
			nonAccept = append(nonAccept, i)
			continue
		}

		fingerprint := fingerprintRuleIDs(s.ruleIDs)
		bucketIndexes := bucketIndexByFingerprint[fingerprint]
		matched := false
		for _, bucketIndex := range bucketIndexes {
			if !slices.Equal(acceptBuckets[bucketIndex].ruleIDs, s.ruleIDs) {
				continue
			}
			acceptBuckets[bucketIndex].states = append(acceptBuckets[bucketIndex].states, i)
			matched = true
			break
		}
		if matched {
			continue
		}

		bucketIndexByFingerprint[fingerprint] = append(bucketIndexByFingerprint[fingerprint], len(acceptBuckets))
		acceptBuckets = append(acceptBuckets, acceptPartitionBucket{
			ruleIDs: slices.Clone(s.ruleIDs),
			states:  []int{i},
		})
	}

	partitions := make([][]int, 0, len(acceptBuckets)+1)
	if len(nonAccept) > 0 {
		partitions = append(partitions, nonAccept)
	}
	for _, bucket := range acceptBuckets {
		partitions = append(partitions, bucket.states)
	}
	return partitions
}

// fingerprintRuleIDs narrows candidate buckets before full rule-ID slice comparison.
func fingerprintRuleIDs(ids []uint32) ruleIDsFingerprint {
	hash := uint64(1469598103934665603)
	for _, id := range ids {
		hash ^= uint64(id)
		hash *= 1099511628211
	}
	return ruleIDsFingerprint{hash: hash, length: len(ids)}
}

// splitPartition refines one partition group by transition signature.
func splitPartition(md *intermediateDFA, partition []int, stateToPartition []uint32) [][]int {
	groupIndexes := make(map[transitionSignature]int, len(partition))
	result := make([][]int, 0, 2)
	for _, s := range partition {
		key := transitionSig(md, s, stateToPartition)
		groupIndex, exists := groupIndexes[key]
		if !exists {
			groupIndex = len(result)
			groupIndexes[key] = groupIndex
			result = append(result, nil)
		}
		result[groupIndex] = append(result[groupIndex], s)
	}

	return result
}

// transitionSig records which partition each outgoing edge reaches.
func transitionSig(md *intermediateDFA, state int, stateToPartition []uint32) transitionSignature {
	sig := noTransSig
	for idx, target := range md.states[state].trans {
		if target != noTransitionState {
			sig[idx] = stateToPartition[target]
		}
	}
	return sig
}

// ---- Match ----

// Match checks whether input is accepted by the compiled DFA.
//
// The input parameter should already be normalized to lowercase DNS form.
// Match returns whether the input matched any pattern, together with the
// matching rule IDs. The DFA traversal is O(n) in the length of input.
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

// StateCount reports how many DFA states are currently allocated.
//
// It returns 0 for a nil receiver or an empty DFA. Callers typically use
// this for metrics, diagnostics, and capacity planning.
func (d *DFA) StateCount() int {
	if d == nil {
		return 0
	}
	return len(d.states)
}

// ---- DOT output ----

// DumpDot writes a Graphviz DOT representation of the DFA to w.
//
// The w parameter receives a directed graph that visualizes state transitions,
// accepting states, and rule attribution. DumpDot returns an error when d is
// nil or when writing to w fails. It is mainly intended for CLI debugging and
// offline inspection of compiled filter behavior.
func (d *DFA) DumpDot(w io.Writer) error {
	if d == nil {
		return errors.New("nil DFA")
	}
	if d.start == nil {
		_, err := fmt.Fprintln(w, "digraph DFA {\n  rankdir=LR;\n  empty [shape=note, label=\"empty DFA\"];\n}")
		return err
	}

	// Build pointer → index map for output
	stateIdx := make(map[*DFAState]int, len(d.states))
	for i := range d.states {
		stateIdx[&d.states[i]] = i
	}

	if _, err := fmt.Fprintln(w, "digraph DFA {"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "  rankdir=LR;"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  start [shape=point];\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  start -> s%d;\n", stateIdx[d.start]); err != nil {
		return err
	}

	for i := range d.states {
		s := &d.states[i]
		shape := "circle"
		if s.Accept {
			shape = "doublecircle"
		}
		label := fmt.Sprintf("s%d", i)
		if s.Accept && len(s.RuleIDs) > 0 {
			label = fmt.Sprintf("s%d\\nrules:%v", i, s.RuleIDs)
		}
		if _, err := fmt.Fprintf(w, "  s%d [shape=%s, label=\"%s\"];\n", i, shape, label); err != nil {
			return err
		}

		// Group transitions by target to make cleaner labels
		targetChars := make(map[int][]rune)
		for idx, target := range s.Trans {
			if target != nil {
				targetChars[stateIdx[target]] = append(targetChars[stateIdx[target]], indexToRune(idx))
			}
		}
		for target, chars := range targetChars {
			sort.Slice(chars, func(a, b int) bool { return chars[a] < chars[b] })
			label := compactRuneLabel(chars)
			if _, err := fmt.Fprintf(w, "  s%d -> s%d [label=\"%s\"];\n", i, target, label); err != nil {
				return err
			}
		}
	}

	if _, err := fmt.Fprintln(w, "}"); err != nil {
		return err
	}
	return nil
}

// compactRuneLabel formats a character set into a human-readable DOT edge label.
func compactRuneLabel(chars []rune) string {
	if len(chars) == AlphabetSize {
		return "[dns]"
	}
	if len(chars) > 10 {
		return fmt.Sprintf("[%d chars]", len(chars))
	}
	var b strings.Builder
	for _, c := range chars {
		b.WriteRune(c)
	}
	return b.String()
}
