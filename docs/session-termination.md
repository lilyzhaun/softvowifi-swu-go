# Session termination ownership

Owner: `lilyzhaun`. Branch: `fix/session-termination-20261012`.
Base: `6fee5e7efc9fe93da827a5178bfa8e7b9b56c280`.

Scope: session termination, protected INFORMATIONAL delete/redirect, hard
expiration, existing terminal DPD/rekey paths and focused regressions.
The consumer's reconnect backoff is outside this library. No device is
operated from this repository.

RFC 7296 section 1.4.1 requires a deleted IKE SA to close its children and
an empty INFORMATIONAL response. The session must attempt that response
before cancellation. Observers do not own or suppress cancellation.
The first terminal cause survives later shutdown, and blocking/reentrant
observers cannot prevent cancellation or issue another terminal event.
Cleanup errors remain errors even when a peer requested termination.

Validation: production receive-path tests with legacy and modern observers,
reply failure, hard expiration, repeated shutdown and typed Connect result;
full race/shuffle tests and vet. Host results do not establish carrier or
kernel interoperability. Source: the RFC and retained MIT code, no external
client implementation copied.

Implementation: protected delete/redirect finish their reply attempt before
calling the shared one-shot terminal path. `Connect` returns a
`SessionClosedError` after cleanup; its reason survives later `Shutdown`.
DPD and rekey exhaustion use that same owner. A peer IKE deletion is not
followed by a second, locally originated Delete. Runtime redirect targets
are returned to the consumer, with diagnostic fixed endpoints excluded.

Validation: the legacy observer/hard-expire and reentrant reason tests first
failed on the base. Focused tests then passed; full `go test -p 1 -race
-shuffle=on -count=1 -timeout=120s ./...` and `go vet -p 1 ./...` passed
using Go 1.26.0. Consumer fixed-pin integration and device validation remain
separate requirements.
