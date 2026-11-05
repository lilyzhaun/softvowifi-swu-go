# Explicit complete proposal policies

`Config.IKEProposals` and `Config.ESPProposals` accept ordered identifiers for
the complete suites listed below. These are library-local identifiers, not an
import format for another client or a carrier profile. They select existing
implementations; they do not add cryptographic algorithms or carrier defaults.

`nil` retains the existing compatibility offer. A non-nil empty list, unknown
or duplicate identifier, conflicting DH group, or incompatible layout returns
`ErrInvalidProposalPolicy` before `Connect` opens a socket. No default fallback
is attempted. Existing callers that supplied non-empty, previously ignored
strings must migrate to this documented closed set.

Call `cfg.ValidateProposalPolicy()` before storing an editor's candidate policy.
It invokes the same compiler without creating a Session, touching a SIM/socket,
or mutating the configuration. Successful validation is not negotiation evidence;
`Connect` still captures and validates the actual policy it will use.

## IKE suites

Append exactly `-dh14` or `-dh2` to one of these identifiers:

| Identifier prefix | Encryption | Integrity | PRF |
|---|---|---|---|
| `ike-cbc128-sha256-prfsha256` | AES-CBC 128 | HMAC-SHA2-256-128 | HMAC-SHA2-256 |
| `ike-cbc256-sha384-prfsha384` | AES-CBC 256 | HMAC-SHA2-384-192 | HMAC-SHA2-384 |
| `ike-cbc128-sha1-prfsha1` | AES-CBC 128 | HMAC-SHA1-96 | HMAC-SHA1 |
| `ike-cbc256-sha256-prfsha256` | AES-CBC 256 | HMAC-SHA2-256-128 | HMAC-SHA2-256 |

The suffix binds MODP group 14 or 2 to the complete suite. All entries in one
offer must use the same group, matching the single KE payload. A nonzero
`IKEDHGroup` must agree; zero uses the explicit suite's group. These options
preserve existing compatibility capabilities, not a recommendation to choose
SHA1 or MODP group 2.

An empty layout or `multiple-complete` sends distinct, consecutively numbered
complete proposals in the requested order. `single-combined` is accepted only
when its Cartesian product equals the supplied complete set. For example, the
128/256-bit SHA256/PRF-SHA256 pair can be combined; combining the SHA256 and
SHA384 suites would introduce unrequested cross-combinations and is rejected.
This follows [RFC 7296 section 3.3](https://www.rfc-editor.org/rfc/rfc7296#section-3.3).

## Child suites

| Identifier | Encryption | Integrity |
|---|---|---|
| `esp-gcm256-noesn` | AES-GCM-16 256 | AEAD |
| `esp-gcm128-noesn` | AES-GCM-16 128 | AEAD |
| `esp-cbc256-sha256-noesn` | AES-CBC 256 | HMAC-SHA2-256-128 |
| `esp-cbc128-sha256-noesn` | AES-CBC 128 | HMAC-SHA2-256-128 |
| `esp-cbc128-sha1-noesn` | AES-CBC 128 | HMAC-SHA1-96 |
| `esp-cbc256-sha512-noesn` | AES-CBC 256 | HMAC-SHA2-512-256 |

These six retain no ESN. Each also has a complete `-esn` variant with the same
encryption/integrity tuple; mixed-mode lists select only their explicit tuples.
Legacy `EnableESN=true` selects ESN for nil-list offers and conflicts with an
explicit list containing a `-noesn` suite. Mode is captured with the policy,
not read from later Config changes. See [ESN](esn.md) for data-plane limits.
`Config.ChildPFSGroup` is a separate, captured library-local uint16: zero
preserves no additional Child DH; 14 enables fresh MODP14 only for Child rekey
in CREATE_CHILD_SA. Other values are rejected before transport use, without
downgrade or automatic group switching. Initial IKE_AUTH Child still has no
independent KE or DH transform. See [Child rekey PFS](child-rekey-pfs.md).
Initial Child and local Child rekey use the same
allowed set. Local rekey prefers the negotiated current suite, preserving the
order of the remaining allowed alternatives. It never restores excluded
default suites. Incoming rekeys retain the existing negotiated-suite checks.

## Capture and compatibility

The complete IKE/Child/PFS policy group is captured at first protocol use, before
`Connect` opens the transport. COOKIE retries keep the original offer; later
changes to input slices or PFS (including zero-to-14 with nil IKE/ESP lists)
cannot change initial Child or rekey policy. Callers
must create a new Session to change the group and must not concurrently mutate
Config while it is being captured. Callback setup such as `OnReady` keeps the
existing API lifecycle.

`InitialIKEProposalNumber` and `InitialChildProposalNumber` retain their legacy
fresh-session compatibility behavior for nil policies. A nonzero index conflicts
with an explicit policy of that protocol; callers must narrow its complete
identifier list in a new Session instead. Response validation still binds to the
actual encoded offer, including proposal numbering, transforms and attributes.

Tests use synthetic inputs and loopback peers. Wire selection, protected AUTH
and rekey checks do not establish real SIM, carrier, Android or long-running
interoperability. The original module path, dependency pins, MIT license and
provenance limits are unchanged; no third-party implementation was copied.

Maintenance validation against base `9395b090615d`: direct regressions first
demonstrated ignored policies, with the seven existing UDP scenarios still
passing. The new eight-parent/39-child group then passed. A complete library
run exposed one legacy DH2 COOKIE regression; preserving the captured offer
before revalidation fixed it without changing the old assertions. The final
affected SWu-package run passed 324 parents and 735 children, with two existing
kernel opt-in skips; whole-library vet ran successfully. Other packages retain
their preceding successful run. This is explicitly split host coverage; the
PR's CI separately runs its normal complete suite on the submitted revision.

The additive public validation API was checked in a subsequent complete host
run: 428 parents and 849 children passed, with 14 parent/12 child kernel opt-in
skips; whole-library vet succeeded. Its one-parent/six-child regression checks
valid and invalid policies, unchanged input and absence of socket work.
