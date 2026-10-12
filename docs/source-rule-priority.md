# Explicit source-routing fallback priority

Owner: `lilyzhaun`; branch `fix/source-rule-priority-20261012`; base
`0e1645d077870a07094dc7b102aee6d28dd72ea3`.

Scope: the existing NetTools source-rule producer and an isolated-kernel
regression. Source-address fallback must be ordered after a consumer's
more-specific interface/mark rules. Kernel automatic priorities are relative
to already-installed rules: adding another session after an owner rule at
9000 can put its source fallback before that owner rule. The consumer then
correctly rejects the apparent conflicting route.

Expose an optional positive `SourceRulePriority`; zero retains existing
standalone behavior. The consumer owns the priority contract, not a carrier
branch. Existing source/table ownership and cleanup behavior remain in use.
IPv4/IPv6 isolated-kernel tests check real priorities, repeated installation,
foreign-rule preservation and full namespace cleanup. No device operations
or private identifiers are used in this repository.

Validation: with the configuration field present but not consumed, the real
IPv4/IPv6 kernel allocated priority 8999 before the existing rule at 9000
(RED). Consuming the positive configured priority makes both families use
9001 (GREEN). The source/table shared-owner, repeated-add and stop-one/keep-
another canary tests also passed in an explicitly isolated network namespace,
restoring its baseline. Full non-privileged race/shuffle tests and vet passed;
their opt-in kernel skips are not counted as those isolated results.

Consumer configuration, fixed pin and actual-device validation are pending.
