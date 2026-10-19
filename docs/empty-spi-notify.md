# Empty-SPI IKE_SA_INIT Notify Protocol ID handling

Owner: `lilyzhaun`. Branch: `fix/ike-empty-spi-notify-20261019`.
Base: `36ca19c8e1499874253d45c8995a8965517eca85`.

Scope: for a single-Notify `IKE_SA_INIT` response already bound to the offered
request header (`SPIi`, major version 2, response role, `IKE_SA_INIT` exchange,
`MessageID == 0` and exact packet length) whose Notify `SPI` field is empty,
ignore all `ProtocolID` values (`0..255`) on receipt as required by RFC 7296
section 3.10. Existing typed handling is preserved: valid 1..64-byte `COOKIE`
challenges request an unchanged retry, `NO_PROPOSAL_CHOSEN` and `REDIRECT`
retain their existing paths, other single on-wire error notifications (`1..16383`,
with 2-byte group validation for `INVALID_KE_PAYLOAD`) return `InitNotifyHintError`
unwrapping to `ErrInitResponse`, and status notifications remain rejected without
becoming hints. Non-empty `SPI` notifications, unbound headers, empty/oversized
or duplicate `COOKIE` payloads, and cross-proposal, proposal-number or DH-group
mismatches remain strictly rejected. No public API is added, and no algorithm,
retry timer or authentication rule is changed.

References: RFC 7296 section 3.10 (Notify Payload Format: if the SPI field is
empty, `Protocol ID` must be sent as zero and must be ignored on receipt) and
section 2.6 (`COOKIE` retry). The change updates the existing MIT-licensed code
using Go's standard library; no external implementation is copied. Module path,
copyright and unknown upstream provenance remain unchanged.

Validation: direct failing tests (`Test_InitSingleNotifyEmptySPIIgnoresProtocolIDAndPreservesGuards`
and `Test_ConnectUDP_CookieProtocolOneRetriesUnchangedAndReachesProtectedAuth`)
before the one-line fix in `pkg/ikev2/init_response.go`, updating the prior
empty-SPI protocol test case to require a non-empty SPI while preserving non-empty
SPI and malformed rejections, followed by complete race and vet checks:
`GOMAXPROCS=1 GOMEMLIMIT=256MiB go test -p 1 -race -shuffle=on -count=1 -timeout=120s ./...`
(1214 passing test events, 26 existing opt-in kernel skips, 0 failures),
`GOMAXPROCS=1 GOMEMLIMIT=256MiB go vet -p 1 ./...` and `git diff --check`.
Protocol and loopback tests do not establish live network authentication or
end-user service.
