package automaton

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func scaledHeavyTestCount(regular, underRace int) int {
	if raceEnabled {
		return underRace
	}

	return regular
}
