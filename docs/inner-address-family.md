# Captured inner address family

Task base: `34dbb4c957ab69e94d32253638c9f2616ae3306e`; branch
`feat/inner-address-family-20261107`. Scope: Config/Session capture, initial
IKE_AUTH CP/TS construction, direct regressions and this API documentation.
No dependency, licence, provenance, endpoint selection or kernel policy change.

`Config.InnerAddressFamily` selects the initial Child request. Accepted values
are empty, `ipv4`, `ipv6` and `dual-stack`. Empty retains the original dual-stack
request and ordering. The value is captured by `NewSession`; later caller edits
require a new Session. It is independent of `RemoteAddressFamily`, DNS endpoints,
APN/IDr, SIP, interface MTU, algorithms, identity and actual assigned addresses.
The caller selects home/roaming policy; the SDK does not infer roaming or OEM
configuration. IPv6 does not change the configured interface MTU.

`ipv4` requests IPv4 address/DNS/P-CSCF and IPv4 TSi/TSr only. `ipv6` requests
IPv6 address/DNS/P-CSCF (including the original assigned-P-CSCF attribute) and
IPv6 TSi/TSr only. Dual stack preserves the original IPv4-then-IPv6 order.
Unsupported strings return `ErrInvalidInnerAddressFamily` with a fixed safe
message before Connect opens a socket, resolves DNS or reads/authenticates a
SIM. Direct initial AUTH construction rejects the same captured invalid value.

The existing frozen-request CP/TS validation and transaction commit rules remain
authoritative. A single-family request must not accept another allocated address
family or unoffered TS. Dual-stack partial allocations retain the existing RFC
7296 handling; optional server attributes are not generically forbidden. Only
usable allocated/selected families enter runtime CP, routes and Child policies.

## Validation record

Declaration/capture-only source `7617e7c0bf0d52f053553cff47143a519546006f2e6821eb8de0c920c7b79d7d`,
task `9b732673f9134af3bc955c3450d802a2`: actual protected UDP AUTH1 and its
frozen request both failed for IPv4/IPv6 because the legacy consumer still
requested both families. Two parents failed; four single-family children
failed and four empty/explicit-dual controls passed. No compile, race, panic
or timeout failure was observed. The independent peer verifies HMAC/decrypts
AUTH1; it does not complete AKA.

Behavior source `018b1bfd9396556d2c208791926cf723020949ca7cb7ddf4600fc5dcf107d32e`,
focused task `d480d13623064e8398bf9f2f6bb49b8c`: 43 parents and 155 children
passed; the existing kernel-XFRM MTU opt-in test was skipped. All five new parents
and 41 new children passed, including protected AUTH1, immutable request capture,
authenticated final replies, inactive-family filtering/routes, rejection with
no commit, and invalid-policy rejection before socket/DNS/SIM. The command
used Go1.26.0, race/shuffle/count=1/vet=all; no compile/race/panic/timeout failure.
The subsequent test-only strengthening additionally requires rejected final
replies to return the initial-Child validation error, rather than any earlier
AUTH/decode error. Production bytes are unchanged from the focused pass.

Full source `e18336103d46abee32079cdeefd50df9caba00bd98b48f48f8f06a33374b2f24`,
input `d71dd820add9edb3b465dd32d770442067cf7a9d395c28d432afbf302f67d02f`,
task `3b2c6233723a41fba50990e64f4418ee`: the once-only `go test -json -p 1
-race -shuffle=on -count=1 -timeout=120s -vet=all ./...` and subsequent
`go vet -p 1 ./...` both exited zero. 534 parents/1121 children passed;
18 parents/12 children retained their existing explicit isolated-kernel
namespace skips. Seven packages passed; one package had no tests. No new test
skips, compile failures, race reports, panics or timeouts. All five new parents
and 41 new children passed; all 15 negative replies reached authenticated
initial-Child CP/TS rejection and left algorithms, CP, selectors, Child SAs,
ticket callbacks and notify/transcript state uncommitted.

The operation took 86.990 seconds including fresh snapshot preparation,
transport and result collection; the test command took 42.381 seconds and
independent vet 25.708 seconds, within the shared 240-second command budget.
Lock acquisition was below 0.001 seconds. These are contained intervals, not
additive end-to-end durations. All three numbered maintenance tasks sent one
terminal notification each. Complete input/result archives and original Go JSON
remain in the task's private evidence tree. Every input/result member's archive
mode, size and SHA and the request/receipt bindings were separately checked offline.
This final documentation-only receipt is not a new tested source snapshot.
Host checks do not establish carrier interoperability or Android kernel support.

Maintenance-module execution is an explicit exception to the consumer-only
`remote.py` entry: fresh complete tracked/unignored source, including testdata,
is bound by file mode/size/SHA and transferred to a new independent directory on
shiyanpc. Extraction, tests and result sealing hold the same exclusive
`/srv/softvowifi/build.lock`. No consumer replace/module cache edits or old
session driver/snapshot reuse. GOMAXPROCS=2, package parallelism 1, race/shuffle,
count=1, 120-second package timeout and a 240-second cumulative command budget.
Each numbered remote task receives one terminal notification. No device/kernel
experiment, commit, push or integration is part of this working-tree candidate.
