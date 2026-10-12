# Authenticated IKE-scoped AUTH_LIFETIME interoperability

## Task and boundary

- Owner: `lilyzhaun`; branch `fix/auth-lifetime-ike-scope-20261012`, base
  `main 0cc1f406ce01`; the starting tree was clean. This is a generic final
  post-EAP representation fix, not a carrier/device policy or a support claim.
- Production scope: `pkg/swu/state_auth.go`, `ike_auth_verify.go`, one small
  CP-order ingress helper, direct independently authenticated wire regressions
  and normal loopback `Connect` tests. Existing algorithms, offers, transcripts,
  identity, authentication, CP/TS rules, ownership and dependencies are unchanged.
- [RFC 4478 section 3](https://www.rfc-editor.org/rfc/rfc4478.html#section-3)
  specifies AUTH_LIFETIME/type16403 with protocol zero, no SPI and four lifetime
  bytes. An observed authenticated peer uses protocol IKE/1. This is a peer
  deviation, not a claim that RFC 4478 permits it. Only this IKE-wide advisory
  has the equivalent scope admitted; AH/ESP/unknown protocols, SPI, duplicate or
  malformed lifetime fields remain rejected. Other recognized status notifies
  retain their protocol-zero rules.
- [RFC 7296 section 2.19](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.19)
  requires a sender to place CP before SA. The receiving post-EAP final ingress
  may represent a single same-message CP before its single SA without changing
  any payload value or the original authenticated wire/transcript. Duplicates
  or missing CP/SA are not normalized. The strict lower-level validator and
  all original invalid-order/CP/SA/TS regressions remain unchanged.
- Responder AUTH and encrypted packet validation are not optional. Bad AUTH,
  replay transcript, selection, addresses or selectors never commit Child SA,
  CP, TS, lifetime, ticket or callbacks. No plaintext acceptance, security
  bypass, new retry, global learning, configuration override or carrier branch.
- RFC text and retained code/Go standard-library tests are the only sources;
  no external implementation is copied. MIT copyright, original module path,
  fixed dependencies and unknown upstream provenance remain unchanged.

## Validation status

- Three protocol-IKE lifetime leaves and two reordered-CP leaves were direct
  behavioral RED on the original implementation (no compile failure). The
  minimal implementation passes all five, the existing strict lower-level
  CP-order negative, and the original AUTH/CP/TS/selection guards.
- A normal loopback `Connect` peer independently checks AKA, both IKE AUTH
  directions, outer ICV, unchanged identity/transcript and exact lifetime. Both
  canonical and equivalent IKE-scope/CP-last cases establish a complete Child
  with one SIM invocation; privacy checks are unchanged.
- One full `go test -p 1 -race -shuffle=on -count=1 -timeout=120s ./...` run:
  1040 passing events, no failures or races, 22 existing isolated-kernel opt-in
  skips; seven test packages pass and one package has no tests. Full `go vet
  -p 1 ./...`, formatting and diff checks pass. CI and reviewed merge are
  tracked by this maintenance PR; the consumer must pin the actual reviewed
  remote revision before building.
- This change does not establish a live subscriber tunnel, IMS registration,
  SMS/voice, kernel ownership, long-term rekey or repeated authentication.
  The existing AUTH_LIFETIME scheduling versus RFC 4478 reauthentication
  limitation remains outside this fix; do not present rekey as reauthentication.
