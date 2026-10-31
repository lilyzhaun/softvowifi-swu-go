# Negotiated security snapshot

This scoped change adds a narrow, read-only `Security` member
to `SessionSnapshot` for a currently authenticated IKE/Child selection. It must
report the actual selected transforms, not the first proposal, caller choices or
a compatibility default.

The intended value contains numeric encryption/integrity identifiers and key
lengths; IKE also reports PRF/DH, while Child reports ESN and additional PFS.
No keys, SPIs, identities, endpoints, tickets or complete Config are part of this
new member. Returned values must not alias Session state. Missing authentication,
failed final AUTH and a canceled/retired owner must leave it unknown. These are
negotiation facts, not an independent kernel-state or device acceptance claim.

The initial regression uses the existing independent UDP AKA peer, including
AUTH transcript verification and a fourth-proposal selection. It also checks
pre-authentication, rejected AUTH, caller mutation and retirement. The real
authenticated connection also performs a protected Child rekey from CBC256 to
GCM128 and checks both the new tuple and the unchanged old returned value. Existing
address/CP snapshot members and protocol choices are outside the new projection.

The initial regression failed after a real authenticated `Connect` reached
`Established`: the previous API had no `Security` member. Invalid final AUTH
continued to fail before Child commit. The later alias and retirement assertions
were not reached on that old input. On the new input, the authenticated exchange,
Child rekey, returned-value isolation, immediate cancellation, setup failure and
privacy assertions all pass.

Publication belongs to `Connect` after final AUTH and successful enabled
dataplane setup. A private context gates cancellation immediately and cleanup
retires the projection even if network cleanup fails. IKE rekey requires the
same complete negotiated tuple; Child selection is copied under the existing
Child lock alongside the current SA pair. Merely constructing SA objects does
not authenticate a session or produce this projection.

The focused race/shuffle run passed 31 parent and 41 child tests, with one
existing kernel opt-in skip. A single full-library race/shuffle run passed 443
parent and 868 child tests, with 15 parent and 12 child kernel opt-in skips; vet
also passed. These are host protocol/API results, not kernel readback, device,
carrier or end-to-end service acceptance. No proposal, timer or keying policy was
changed by this projection.
