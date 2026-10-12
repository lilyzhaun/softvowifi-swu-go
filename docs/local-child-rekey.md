# Local Child rekey offer, selection and independent timing

Owner `lilyzhaun`, branch `fix/local-child-rekey-20261012`, base `04680c6`.
Scope: local CREATE_CHILD_SA actual offer/selection binding, selected suite
in kernel arguments and committed metadata, Child-only cooldown/reset, and
normal wire/kernel regressions. No carrier-specific DH/PFS guesses or device
operations in this repository.

RFC7296 sections1.3.3/2.8/2.17/3.3 require a complete offered selection and
new key material for the correct directional SPIs. Current supported suite
must remain available when it is rekeyed. IKE rekey and Child rekey have
different lifetimes; completing one cannot reset or suppress the other.
Source is retained MIT code and the RFC, no external implementation copied.

Implementation: the current complete suite is first, followed by the other
supported original suites with contiguous numbers. An owned encoded SA/TS
offer snapshot binds selection, all mandatory attributes/ESN and unchanged
selectors. The selected integrity/ESN travels with the new pair into kernel
configuration and committed metadata. Child success uses its own timestamp
and reset channel; it cannot advance IKE's cooldown/timer. The inbound map
no longer retains SAs already removed by the existing local kernel retirement.
Reliable old-Delete transactions/complete overlap semantics remain separately
tracked; this change does not claim them from the map correction.

Validation: missing negotiated offers, stale kernel integrity and wrong
timer/reset were RED, then GREEN. Thirteen invalid actual-wire response
variants reject before kernel mutation; explicit Notify14 preserves its
original code and no-mutation assertions. Old fixtures gained complete
negotiated metadata/ESN/TS and select from the actual wire offer rather than
assuming proposal1. Kernel failure/no-commit/both-channel assertions remain;
the mapping failure test corrupts the selected field instead of stale state.
Full low-parallel race/shuffle and vet passed. Explicit isolated kernel tests
verified the peer-retirement canary remains valid and actual GCM256 old SAs
are replaced by selected CBC128/SHA256 states, then cleaned. This is state/
policy proof, not live kernel ESP delivery. Consumer old fixed-pin UDP RED;
new fixed pin and necessary device validation pending.
