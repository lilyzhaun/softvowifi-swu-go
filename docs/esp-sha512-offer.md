# Complete AES-256 / SHA2-512 ESP offer

Owner: `lilyzhaun`; branch: `fix/esp-sha512-proposal`.
Base: `ce3bdedfbb74b483e9bca4b0865c2c76c4287118`.

The implementation already supports AES-CBC-256 and HMAC-SHA2-512-256 in
its crypto and XFRM paths, but the initial Child SA proposals did not offer
that complete combination. Append it as proposal six, with NO_ESN, keeping
the five existing offers and their order. No carrier identifier, address
family, identity, authentication, CP, or retry policy is changed.

The integrity transform is defined by RFC 4868:
https://www.rfc-editor.org/rfc/rfc4868 . Existing crypto implementations and
licenses remain unchanged; no external code or carrier bundle is copied.

The normal encrypted AUTH1 builder first failed the independent six-offer
wire contract. After the repair, all six suites, proposal numbers, SPI,
key lengths and NO_ESN passed; a valid final responder AUTH selecting the
new suite installs 32-byte encryption and 64-byte integrity keys in both
directions. Historical EAP_ONLY and device-identity fixtures remain
unchanged: an independent literal 40-byte proposal extends their expected
wire image, retaining the exact original assertions with adjusted offsets.
Their initial four failures are preserved as a test-baseline transition,
not hidden by weakening the checks.

The complete six-package race/shuffle suite and vet passed after the
targeted regression repair; two packages contain no tests. Kernel opt-in
coverage and real operator connectivity are separate. This is offer
coverage, not a claim that a particular network will accept the session.
