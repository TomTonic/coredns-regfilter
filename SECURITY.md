# Security

If you find a significant vulnerability, or evidence of one,
please report it privately.

We prefer that you use the
[GitHub mechanism for privately reporting a vulnerability](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability#privately-reporting-a-security-vulnerability).
Under the
[main repository's security tab](../../security),
click "Report a vulnerability" to open the advisory form.

We will acknowledge your report within 48 hours and aim to provide a
fix or mitigation within 7 days for critical issues.

## Security Design

### Input Validation
- Internationalized domains are normalized through IDNA lookup processing and
	converted to ASCII punycode before compilation
- Parsed domains are validated against DNS host label constraints (label
	boundaries, label length, and allowed character set)
- Invalid rules are skipped with explicit warning logs that include source
	file and line number
- Per-file parser limits are enforced: max line length `8192` bytes and max
	line count `200000`
- Compile-time limits (MaxStates, timeout) prevent resource exhaustion
- When `disable_RFC_checks` is `off` (the default), every DNS query name is
	validated at query time against RFC 1035 LDH syntax and the IDNA Lookup
	profile (RFCs 5890–5894); names that fail this check are blocked before the
	denylist matcher is consulted. This limits the attack surface for unusual or
	malformed query names.
- When `deny_non_allowlisted` is `on`, every query not present in the allowlist
	is blocked in the denylist phase before the denylist matcher is consulted,
	providing a deny-by-default posture.

### Resource Limits
- DFA compilation is bounded by `max_states` and `compile_timeout`
- Pathological patterns that cause state explosion are rejected
- File watching uses debouncing to prevent rapid recompilation

`max_states` can be set to `0` to disable the state cap. This uncapped mode is
supported for advanced use cases and logs an explicit startup warning.

### No Code Execution
- Filter list contents are never executed or evaluated as code
- Only domain pattern matching is performed
