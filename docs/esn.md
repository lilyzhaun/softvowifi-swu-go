# Captured ESP extended sequence numbers

ESN is opt-in and independent of Child rekey PFS. The original six `-noesn`
suites and their default order remain unchanged. Replace a documented Child
suite's `-noesn` suffix with `-esn` to request its complete ESN tuple. Explicit
lists may contain either mode, without duplicate identifiers or implicit fallback.
Legacy `EnableESN=true` selects ESN for the nil-list compatibility offers; it
conflicts with an explicit list containing a `-noesn` suite.

The policy compiler captures mode with the complete proposals at first use.
Later Config changes cannot rewrite the authenticated owner's policy. Initial
AUTH validates the actual encoded offer before publishing mode to both ESP SAs
and the authenticated security snapshot. Local and peer Child rekeys use new
SA-local counters/windows; a policy flag is not proof of peer selection.

## Userspace ESP

- GCM AAD is SPI followed by the complete 64-bit sequence; its eight-byte
  explicit IV is that reserved sequence. CBC authenticates the high word after
  the ESP header, IV and ciphertext. The high word is not sent separately.
- Reservation is atomic. ESN/noESN refuse further transmission at the 64/32-bit
  limit instead of wrapping. The legacy `NextSequenceNumber` accessor returns
  zero on exhaustion; `Encapsulate` returns the error and emits no packet.
- ESN receive uses a fixed 64-packet window, reconstructs the high word using
  RFC 4303 Appendix A, and commits only after authentication and trailer checks.
  Invalid or duplicate packets cannot advance it. CBC ESN requires an integrity
  algorithm. The legacy noESN wire format and receive behavior are unchanged.

## Kernel ownership and limits

ESN requests use a positive replay window; an omitted window resolves to 32.
The legacy noESN OUT-zero/IN-32 behavior remains. GET must confirm the ESN flag
and static ESN window before ownership is accepted. Drift blocks UPDATE/DELETE.
Live high/low sequence words and bitmap are readback, not owner identity or
inputs for restoring sequence state during a lifetime update.

The fixed netlink replacement is
`github.com/lilyzhaun/softvowifi-netlink@v0.0.0-20261105000017-d35d90655c7d`.
Callers with a top-level module must explicitly pin their own replacement;
Go does not inherit dependency-module replace directives.

Validation is layered: independent standard-library ESP peers, actual protected
AUTH and UDP Connect, local/peer rekey consumers, and fake-netlink ownership
regressions are distinct. An explicitly isolated Linux 6.8 test separately
checks manager GET, actual output sequence 3, lifetime-update preservation and
sequence 4, then exact cleanup. It does not exercise a kernel high-word rollover,
Linux 7 explicit-direction behavior, Android, real SIM/carrier ESN negotiation,
seamless MOBIKE or long-term service. Default CI skips privileged kernel tests.

Only RFC 4303 Appendix A, RFC 4106 section 8 and RFC 7296 transform semantics,
the existing implementation and Go standard crypto were used; no external
client configuration, OEM values or implementation were copied. MIT copyright,
module identity and unknown original upstream provenance remain unchanged.
