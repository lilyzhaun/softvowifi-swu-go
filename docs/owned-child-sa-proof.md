# On-demand owned Child-SA readback

`Session.ReadChildSAProof(ctx)` reads the currently installed XFRM Child pair
and, when known, the most recent predecessor. It does not modify SAs, policies,
configuration or connection state, and does not run in the background.

## Evidence and lifetime

- `State=verified` means both current directions matched their confirmed owned
  installation snapshots during this sample. `Current.Inbound/Outbound.Limits`
  contains kernel `TimeSoft/TimeHard` in seconds, including an observed zero.
  These are local ESP-SA limits, not IKE/AUTH_LIFETIME, negotiated or remaining
  lifetimes, and not evidence of application traffic.
- `Previous.State=not-observed` means no predecessor was captured. Legal peer
  rekey overlap is reported separately from retirement. Only two actual
  ENOENT/ESRCH results produce `absent`; DELETE success and removal from an
  ownership map do not. An existing/reused tuple is never deleted by readback.
- Unavailable ownership, mismatch, read errors, cancellation and an in-flight
  generation change do not yield a verified sample. The snapshot is not a
  promise that another actor cannot change the kernel after the observation.
  It does not detect a foreign replacement that reproduces every captured
  parameter exactly; no installation-age or anti-ABA kernel guarantee is made.

Initial setup, local and peer rekey, old-pair deletion, MOBIKE and cleanup
invalidate the small readback view before mutation. Readers capture and recheck
the authenticated owner and epoch, without holding lifecycle locks over I/O.
Failed or overlapping mutations conservatively withdraw the current proof.

There are at most four exact GETs with a one-second context budget. Each uses a
dedicated XFRM handle with a socket timeout capped at 250ms and the remaining
deadline. Cancellation is observed around bounded socket calls, not claimed to
interrupt a syscall instantaneously. No List/Flush/Add/Update/Delete call is
made by the read API. Temporary returned keys are cleared after comparison.

`driver.CaptureOwnedSA` only captures a manager's confirmed records; the opaque
`OwnedSAToken` has no writable or JSON tuple representation. Driver readback
returns only fixed status strings and limits, never a raw netlink object/error,
endpoint, SPI, key or key hash. Callers must not accept user-selected tuples as
an alternative to their owning Session.

## Validation and boundaries

Owner: `lilyzhaun`; branch `feat/owned-child-sa-proof-20261102`; base
`94fc18e053ba1aa78f02904e36a0ec91d1286c97`.

Direct tests cover actual manager installation records, false DELETE ACKs,
absence/error distinction, tuple reuse, parameter/key mismatch, cancellation,
lock contention and same-byte updates during a read. Session tests control
read timing only; they are not substitutes for kernel installation evidence.

The full non-privileged race/shuffle run passed 491 top-level and 934 subtests,
with 27 existing kernel opt-in skips; vet passed. An initial new test referenced
the wrong configuration field names and failed compilation; that result is
not classified as a behavioral regression.

Explicit child-network-namespace tests on Linux 6.8 passed local GCM-to-CBC
rekey/current-pair/old-tuple readback and peer overlap/Delete with a foreign
canary. Its initial/MOBIKE test was refused by the existing SA-direction guard;
the unchanged base version fails at the same guard on that kernel. Linux 7.0
passed initial/MOBIKE limits and preserved AddTime/hard deadline, plus peer
overlap/retirement. The GCM fixture's initial AddSA returned EINVAL there,
before rekey/proof assertions. These are separate samples, not a single all-pass
kernel matrix; neither failure is weakened or converted into a skip. Each
namespace's owned cleanup and process/namespace teardown remained in place.

No Android, live SIM/carrier, natural long-window or application-business
validation is asserted. Existing MIT/module/dependency pins and unknown
upstream provenance are unchanged. The implementation uses this repository's
ownership and lifecycle code, the pinned netlink GET API and Go context/sync
facilities; no external client configuration/defaults or OEM values were copied.
