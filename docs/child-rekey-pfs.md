# Child rekey PFS maintenance task

Owner: `lilyzhaun`. Branch: `feat/child-rekey-pfs-20261105`.
Base: `84097b5aae17aff2c8348dc588cf5c794f05390c`.

Scope: `pkg/swu` captured Child policy, local/peer CREATE_CHILD_SA rekey,
fresh MODP14 KE and KEYMAT, direct synthetic regressions and isolated Linux
kernel installation/retirement. Existing transaction, ownership, cancellation,
response replay and initial IKE_AUTH rules must remain intact. No ESN,
initial-Child independent KE, new algorithm, carrier/default configuration,
module/dependency/license change or device operation is included.

## Contract

`Config.ChildPFSGroup` is a library-owned uint16, not another client's imported
configuration syntax. Zero keeps the no-additional-DH baseline; 14 enables
MODP2048 for CREATE_CHILD_SA Child rekey only. Unsupported values fail local
validation before transport setup. IKE DH selection remains independent.

The entire proposal policy is captured at first protocol use, including nil
suite lists and PFS zero. Later Config changes do not hot-enable PFS or change
an existing Session; callers create a fresh Session instead. Initial IKE_AUTH
Child retains no independent KE or DH transform, even when configured for14.
All current ESP identifiers still mean no ESN; this task does not implement ESN.

Local requests bind every actual allowed complete ESP proposal to DH14 and one
fresh KE. Responses must match the owned encoded offer, with exactly one
matching valid KE; missing, duplicate, bad, wrong-group or unoffered DH cannot
silently select no-PFS. Peer requests enforce the same group/KE pairing, retain
the negotiated complete suite and exact selectors, then produce fresh KEr.
An INVALID_KE response only advertises configured14; received INVALID_KE does
not switch groups or automatically retry with weaker/unconfigured DH.

The existing derivation consumes `prf+(SK_d, new_shared|Ni|Nr)`; shared secret
and both nonces belong to this exchange, and key direction follows the exchange
initiator rather than the original IKE initiator. Existing CBC integrity and
GCM per-direction salt layouts are retained. The original IKE DH is untouched.

Peer transactions still stage kernel changes, send a protected response, then
publish the pair; install/send/cancellation failures roll back via the existing
undo path. Cancellation during send is checked before publication. Local
installation failures/cancellation never publish or send old Delete; kernel
resources already installed remain owned for the existing lifecycle cleanup,
not falsely reported as a complete local rollback. Cancellation before old
deletion keeps the old states until that cleanup. Response replay returns the
original bytes without another DH operation or install. Predecessor Delete
and final namespace cleanup preserve unrelated owners.

`Snapshot().Security.Child.PFS` reports only the group of the successfully
committed actual Child rekey. Initial authenticated Child reports0 even with
policy14; failed exchanges retain the preceding tuple. No-PFS remains0;
unconfirmed/canceled/retired authentication still exposes no Security fact.
PFS policy, authenticated selection and actual kernel readback are separate
facts, not interchangeable proofs of traffic or long-term interoperability.

## Validation

The first wire regression uses JSON to remain compilable before the public
policy field exists. It reached the encrypted production CREATE_CHILD_SA
request and failed specifically on absent KE, with the old no-PFS mock-kernel
and no-kernel success controls passing. Compilation failure or failure to reach
the first packet is not counted as behavioral RED.

The initial focused run also retained a test-fixture failure: the synthetic peer
pair lacked its authenticated current outbound policy, so the existing strict
snapshot assertion correctly distinguished an empty allocated slice from nil.
The new peer fixture now installs that policy; no existing assertion was
removed or weakened. Independent fixed HMAC-SHA256 vectors, math/big MODP peer,
standard AES-CBC/HMAC wire opening/sealing, all six ESP key layouts and both
directions, real UDP authentication-to-PFS snapshot, invalid KE/DH, ownership,
cancellation, retry and predecessor retirement are covered. The two key
directions are checked separately rather than inferred from configuration.

The first full run preserved ten parent/child failure events from four legacy
tests whose fixtures changed nil-list policy after their initial builder had
already captured it: INIT single-offer numbering, XCBC combined layout, initial
Child single-offer numbering and private-CP fresh single offers. Their original
wire/selection/unrelated-payload/authentication assertions remain intact. The
fixtures now supply layout/numbering before first use or create a distinct fresh
owner, rather than clearing/replacing the original captured policy or restoring
production hot reads. This is the reason for the next focused verification and
one complete rerun; the original full failure log remains retained.

The corrected complete race/shuffle run and full vet passed. Its subsequent
isolated-kernel run passed peer PFS installation, replay, old-SA retirement and
cleanup, but the local case failed during initial canary setup with EINVAL,
before sending a PFS request. That local mock fixture supplied a positive128
replay window to explicit outbound SA on Linux7; the peer fixture used0 and
the existing direction-aware driver default. The new kernel PFS fixture now
explicitly uses that same default (outbound0/inbound32) for both directions;
production replay handling, ESN and old replay tests are unchanged. This is
not evidence that positive outbound128 is supported on that kernel. Only the
affected kernel test/compile and vet are rerun; the successful whole-library
run remains separate evidence with its original input binding.

### Final host evidence (2026-11-05)

All manual validation used a hash/mode-verified source archive, the shared
exclusive build lock, the existing caches, `GOMAXPROCS=2`, `-p1` and bounded
stage deadlines. Each task's temporary remote source tree was removed. Tests
used `-count=1` (no cached test-result success); compiler/module caches remained
enabled. Compile time versus cache reuse is not separately measurable from
these logs and is not claimed as a clean rebuild.

| Stage | Task | Result |
|---|---|---|
| First real encrypted wire RED | `96f21b18a3c249b39daeccb76a19191f` | 1 expected failure (absent KE), 3 pass events from the old no-PFS control |
| Initial focused diagnostic | `adc48f65922a4e1ea563b6f776433522` | 203 pass / 22 fail / 3 opt-in skips; only the new synthetic peer fixture precondition failed |
| Focused GREEN | `0931e43327c44d2198568a4c7d0b7883` | 225 pass / 0 fail / 3 opt-in skips |
| Cancellation-boundary focused GREEN | `9ead23874156475bb1a53e9f5665db7a` | 227 pass / 0 fail / 3 opt-in skips |
| First full diagnostic | `0766af6da91a4a8db40c41cafba2cbe3` | 1504 pass / 10 fail / 28 opt-in skips; four legacy post-capture fixture mutations identified above |
| Expanded affected GREEN | `e2f6e5e8a1444952b4453c1e1c27dcd3` | 451 pass / 0 fail / 3 opt-in skips |
| Full library and vet | `b5773bb832c8455a8e57c9bc2ffb629e` | 1514 pass events (503 parent / 1011 child), 0 fail, 28 opt-in skips; 7 test packages pass, 1 no-test package; full vet passed. Later kernel stage retained the local setup failure / peer success, so the overall task exit was1 |
| Affected isolated kernel and vet | `0379987f1ef64cf4920f3829f943a411` | full vet and race test-binary compile passed; local and peer kernel cases passed (3 events), no failure/skip |

The successful full library ran exactly
`go test -p 1 -race -shuffle=on -count=1 -timeout=120s -json ./...` and
`go vet -p 1 ./...`. The isolated run used the compiled race binary inside a fresh
network namespace, refused the ordinary host namespace, installed actual
local/peer PFS-derived key bytes, observed new-SA presence and old-tuple absence,
verified byte-identical response replay, preserved a separate canary owner,
and explicitly checked empty owned XFRM state/policy cleanup.

Full-library input digest:
`f2ffb88d3fb6df4d86c4456b385ddad48ab17d54c3ec08dffdf4ef5b6e55fffb`.
Final affected-kernel input digest:
`e98ca67ce009c7de8b863b995efbc21c204cfe9be7e8473fb0a0cba4887e50c6`.
Their production Go files are identical; only the new kernel fixture and task
documentation changed. Later evidence-only documentation does not require a
third full compile. CI against the submitted head remains separate evidence.

Gitleaks8.30.1 scanned both the complete candidate and the complete base tree,
with original modes/hash binding, unchanged scan rules and inline-ignore
processing disabled. Each had the same two redacted hits: the published RFC4186
test vector in `aka_reference_test.go` and synthetic key-variable assignment in
`fragment_transaction_test.go`. Both complete files were independently reviewed
and byte-equal to the base. Raw findings remain2, newly introduced findings0;
they are not rewritten as a zero-hit scan or added to an expanded allowlist.

These synthetic wire, authenticated loopback UDP and isolated Linux results do
not establish Android behavior, a real carrier natural rekey/long-term session,
all lifecycle paths or ESN support. Consumer pin adoption and device validation
remain independent subsequent work.

Protocol references: RFC7296 §§1.3, 2.17, 2.8 and RFC3526 group14. Existing
project crypto and transaction code are reused, without external implementation
copying or changes to the original provenance qualifications.
