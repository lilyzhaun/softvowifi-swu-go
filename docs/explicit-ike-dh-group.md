# Explicit IKE DH group compatibility

Owner: `lilyzhaun`. Branch: `fix/explicit-ike-dh-group-20261019`.
Base: `4f7adda556af7b2a65f05b0de8e583e0c777b53d`.

Scope: support explicitly selected MODP group 2 alongside the existing group 14
through initial key generation, immutable offer validation and existing IKE
rekey paths. Zero configuration retains group 14. No automatic downgrade on
unauthenticated errors, algorithm scanning or relaxed proposal-number matching.
Group 2 is legacy compatibility, not a recommended default.

References: RFC 2409 section 6.2 (public MODP group parameters), RFC 7296
sections 2.7, 3.3 and 3.4 (offer selection and KE). The implementation extends
the existing MIT-licensed code using Go's standard library; no external
implementation is copied. Module path, copyright and unknown upstream
provenance remain unchanged.

Validation: direct failing tests before implementation, focused crypto/initial
exchange/rekey checks, then the applicable complete race and vet checks:
`GOMAXPROCS=1 GOMEMLIMIT=256MiB go test -p 1 -race -shuffle=on -count=1 -timeout=120s ./...`
(1195 passing test events, 26 existing opt-in kernel skips, 0 failures),
`GOMAXPROCS=1 GOMEMLIMIT=256MiB go vet -p 1 ./...` and `git diff --check`.
Protocol tests do not establish carrier authentication or end-user service.
