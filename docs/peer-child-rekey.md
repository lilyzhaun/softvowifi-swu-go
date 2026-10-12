# Peer Child rekey transaction

Owner `lilyzhaun`, branch `fix/peer-child-rekey-20261012`, base `2b03152`.
Scope: protected peer CREATE_CHILD_SA(ESP), exact current suite/REKEY_SA/TS
selection, exchange-direction KEYMAT, staged kernel installation and rollback,
reply replay, Child state publication and old-pair retirement. Local offer
expansion/selection and timer separation remain the following slice.

RFC7296 sections1.3.3/2.8/2.17/3.3: peer inbound SPI is our outbound SPI;
KEYMAT's first half is the exchange initiator-to-responder direction (our
inbound). A complete supported proposal must be selected with attributes.
Unknown predecessor/missing REKEY_SA/invalid TS must not install or publish.
Kernel failures must not accept a new SA; ambiguous rollback ends the session
through existing owned cleanup. Old-pair Delete must not retire the new pair.
No device operations, real identities or external implementation copied.

Implementation: exact current-suite and unchanged-TS selection (TS changes
are rejected rather than claiming unsupported narrower kernel enforcement),
first KEYMAT half used inbound for a peer-initiated exchange. Kernel mapping
is shared with the existing local installer; peer preparation retains both
old SAs and rolls back policies/new SAs on failed install/send. An inbound
policy with mandatory ESP and the same if_id accepts the two owned generations
during overlap. Successful response precedes memory publication. One bounded
old pair plus response record absorbs rekey repeats and retires on old Delete
or a three-minute expiry; uncertain rollback/retirement ends the session.
Child pointer/map publication and runtime data-plane/status readers use a
small separate state lock; no receive lock is held awaiting a peer response.

Validation: six-suite production dispatch and independent CBC/HMAC/prf+
oracle were RED, then GREEN. Invalid predecessor/attributes/nonce/TS, kernel
add/policy stages, failed send rollback, duplicate response and old Delete
preserving current pair passed. Full low-parallel race/shuffle/vet passed;
an explicit isolated real-kernel test verified four overlapping SAs plus a
foreign canary, mandatory ESP/if_id policy, old-pair deletion, and owned cleanup
preserving that canary before final removal. This is real kernel state/policy
validation, not proof of actual kernel ESP traffic. Consumer old fixed-pin
real UDP/ESP failed on outgoing SPI; its new fixed-pin gate/device proof is
pending. Source remains original MIT/RFC7296; no external code copied.

Two additional cancellation regressions were RED before completion: cancel
during installation still accepted/published, and full session cleanup could
remove resources while installation was in flight. Cancellation now rolls
back before sending acceptance, cleanup joins the rekey mutex, and terminal
observers run after releasing that mutex. The final full race/shuffle/vet
gate passed, including all six kernel-suite argument combinations. The old
unreferenced peer-to-local install shim was removed after its caller moved
to staged installation; local installer behavior is otherwise preserved.
