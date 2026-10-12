# Peer-initiated IKE rekey

Owner `lilyzhaun`, branch `fix/peer-ike-rekey-20261012`, base `8afc999`.
Scope: protected CREATE_CHILD_SA(IKE), exact current-suite selection,
one-owner locking, new-SA role and MID handoff, bounded old-SA retirement
and production-dispatch regression. No device operations in this repository.

RFC 7296 sections 1.3.2, 2.8, 2.18 and 3.3 require negotiated transforms
including attributes, fresh DH/nonces, the new exchange initiator's role,
new Message IDs and deletion of the superseded IKE SA without its inherited
children. A successful response cannot precede key derivation. Outstanding
old requests must not collide with a reset MID; busy requests use the existing
TEMPORARY_FAILURE path. Retained MIT code and RFC text only; no client code
copied from another project.

Implementation: the dispatcher owns rekeyMu once; the public entry takes it
before entering the locked helper. Selection retains only the current
supported suite from a complete offered proposal, including AES attributes;
nonce/duplicate/KE/SPI checks reject before acceptance. Derivation precedes
the old-key response. Admission blocks generation handoff while an old
transaction is outstanding; codecs synchronize SPI/key/role snapshots.
DPD shares rekey serialization. A single old context is kept for three
minutes solely to replay its successful rekey response or acknowledge an
old IKE Delete (including byte-identical retries). It cannot delete inherited
children, alter endpoints or fulfill new-generation pending requests.

Validation: dispatcher deadlock and missing AES attribute were RED first.
Focused production dispatch/independent response authentication, malformed
selection/send failure, alternative offer, pending MID0, old Delete/replay
and expiration passed. Full low-parallel race/shuffle and vet passed; after
old-Delete replay and nonce-minimum additions, affected tests and vet passed
again. Initial new busy/retirement fixtures lacked a context and were fixed
before claiming those tests passed. An attempted DH19 fixture was invalid:
the retained crypto library supports only DH14, so no DH19 support is claimed.
Host success does not imply carrier rekey, the complete request replay window,
simultaneous rekey resolution or long-term validation. Consumer real UDP,
fixed-pin and device gates remain separate.

Follow-up `fix/rekey-reset-publication-20261012`, base `f766795`, same owner:
consumer real UDP completed the rekey but race detection exposed timer
startup replacing a reset channel concurrently with the immediately active
dispatcher. Constructor publication must precede control-plane exposure;
the two timers must keep those channels rather than replacing them.
