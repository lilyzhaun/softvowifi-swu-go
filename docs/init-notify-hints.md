# Unauthenticated IKE_SA_INIT notification hints

RFC 7296 §2.21.1 requires care with unauthenticated errors. A rejected INIT
notification can help diagnose a failure without authorizing a parameter change
or consuming the pending exchange.

`DecodeInitResponse` now returns `InitNotifyHintError` for a structurally valid,
single error Notify that was already rejected. It still unwraps to
`ErrInitResponse`. The reply must match the offered initiator SPI, response role,
IKEv2 major version, INIT exchange, MID zero and exact packet length. Its one
on-wire Notify must have protocol zero and no SPI. Status notifications and
malformed/chained payloads do not become hints. INVALID_KE_PAYLOAD additionally
requires exactly two bytes; the public group number is advisory, never trusted.

The Session records at most four distinct types, once per type. Logs contain
only `authenticated=false`, numeric type, data length, and the two-byte group
number for INVALID_KE_PAYLOAD. No raw Notify data, SPI, address or identity is
retained. An exhausted INIT window retains the same `ErrWindowTimeout` identity
and appends this bounded diagnostic summary. Cancellation and successful
exchanges retain their existing behavior.

No proposal, DH group, request bytes, retry count/backoff, peer endpoint, SA or
key is changed because of a hint. Existing COOKIE, NO_PROPOSAL_CHOSEN and
REDIRECT processing is unchanged. This does not implement INVALID_KE corrective
negotiation or establish a carrier-specific root cause.

## Verification

- Direct receive entry: missing-hint RED, then deduplication, pending/endpoint
  invariants and valid original-offer completion GREEN.
- Header/framing/Notify matrix rejects unbound and malformed inputs; an ignored
  noncritical suffix cannot masquerade as one on-wire Notify.
- Real UDP `Connect`: rejected hint followed by valid suite selection reaches
  protected IKE_AUTH with independent SHA-256 PRF+/ICV/decryption checks.
- Real UDP retransmission stays byte-identical; advancing the test window's
  deadline and exhaustion under its lock returns the annotated timeout through
  normal `Connect` cleanup. Production retry settings are unchanged.

Source: [RFC 7296 §2.21.1](https://www.rfc-editor.org/rfc/rfc7296#section-2.21.1),
the retained MIT code and Go standard library. No external client implementation
was copied; original module path, copyright and unknown upstream provenance stay
unchanged. Synthetic/loopback evidence does not imply carrier/device acceptance.
