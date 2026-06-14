# AI Agent Guidelines

## Project Overview

This is the `filterlist` CoreDNS plugin: it intercepts DNS queries and checks
them against allowlist and denylist filter sets (AdGuard, EasyList, ABP, and
hosts-style lists), blocking or forwarding queries according to configuration.

All source code is Go and managed with Go modules. The top-level package holds
the CoreDNS plugin (handler, setup, RFC name validation); the reusable building
blocks live under `pkg/` (`listparser`, `blockloader`, `matcher`, `automaton`,
`suffixmap`, `watcher`, `metrics`). Matching uses a hybrid suffix-map + DFA
representation; directories are hot-reloaded by a debounced fsnotify watcher.

## Build & Test Commands

```bash
go build ./...          # Build
go test ./...           # Run tests
go test ./... -race     # Run tests with race detector
go test ./... -cover    # Run tests with coverage
golangci-lint run       # Run linter (uses .golangci.yml)
```

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`).
- Use `golangci-lint` with the project's `.golangci.yml` configuration.
- Keep functions focused and under 60 lines where practical.
- Prefer returning errors over panicking.
- Use Go's standard error wrapping: `fmt.Errorf("context: %w", err)`.
- Do not use `panic()` in library code.

### Function and Method Documentation

Every exported function and method must have a godoc comment. Write it
like a good JavaDoc entry but with more emphasis on **context and usage
guidance** than a pure specification:

1. **First sentence**: A concise summary of what the function does,
   starting with the function name (Go convention).
2. **Parameters**: Document each parameter — its type, valid ranges,
   and what it controls.
3. **Return values**: What is returned on success and on error.
4. **Usage context**: When and why a caller would use this function.
   Mention typical call sites, related functions, or common patterns.
5. **Example** (optional but encouraged): A short inline example or
   reference to a testable example (`Example*` function).
6. Use **English** language.

Example (from `pkg/matcher`):

```go
// Match checks input against both the literal suffix map and the wildcard DFA.
//
// The input parameter should be a domain name without trailing dot.
// Returns true if any stored pattern matches, along with all matching rule IDs.
// The suffix map is checked first; if both literal and wildcard patterns match,
// all rule IDs are combined.
//
// In pure DFA mode (no suffix map) the byteIndex table inside the automaton
// handles case-insensitivity, so strings.ToLower is skipped and the
// automaton.DFA.MatchDomain result is returned directly — zero allocation.
//
// Typical usage is on the DNS request hot path: the plugin calls Match once
// per query against the active allowlist and denylist matchers.
func (m *Matcher) Match(input string) (matched bool, ruleIDs []uint32) { ... }
```

Unexported helpers do not require full documentation, but a one-line
comment explaining *why* the helper exists is expected.

## Testing Requirements

- All new functionality must include tests.
- Use table-driven tests where appropriate.
- Maintain at least 80% test coverage.
- Run `go test ./... -race` before submitting changes.
- Fuzz tests are welcome for functions that parse external input.

### Test Documentation

Every test function must have a doc comment that reads **outside-in**.
Structure the comment in this order:

1. **User perspective**: What does the tested code achieve for the end user,
   described in the user's own terminology? Avoid implementation jargon.
2. **Context**: Which module, package, or feature area does the tested code
   belong to? How does it fit into the larger system?
3. **Concrete expectation**: What specific behavior is this test verifying?

Example:

```go
// TestPruneKeepsLatestHourly verifies that the backup pruning logic
// retains exactly one backup per hour for the most recent 24 hours,
// ensuring users never lose their latest hourly snapshot.
//
// This test covers the core retention algorithm in the pruning package.
//
// It sets up a directory with multiple backups within the same hour and
// asserts that only the chronologically latest entry survives while the
// others are moved to the "to_delete" directory.
func TestPruneKeepsLatestHourly(t *testing.T) { ... }
```

For table-driven tests, document the overall test function with the
outside-in structure and give each sub-test case a descriptive name
that reads as an assertion (e.g. `"returns error for empty input"`).

## Commit Messages

- Use imperative mood ("Add feature", not "Added feature").
- Limit subject line to 72 characters.
- Prefix dependency updates with `deps-upd:`.
- Separate subject from body with a blank line.

## Dependencies

- Minimize external dependencies.
- All dependencies are managed via Renovate (see `renovate.json`).
- Run `go mod tidy` after adding or removing dependencies.
- Do not add dependencies with known vulnerabilities.

## Security

- Never commit secrets, credentials, or API keys.
- The `gosec` linter is enabled — do not disable it.
- Validate all external input at system boundaries.
- Use `crypto/rand` for security-sensitive randomness, not `math/rand`.

## CI/CD

- All pushes and PRs are checked by: golangci-lint, go vet, go test, CodeQL.
- Coverage is tracked via gist-based badges.
- Dependency updates are automated via Renovate with automerge for patches
  and minor updates.
- Vulnerabilities are scanned daily via grype_me.

## File Organization

- Keep the top-level package clean; use subdirectories for internal packages.
- Test files live next to the code they test (`foo_test.go` next to `foo.go`).
- Generated code goes in clearly marked directories excluded from linting.
