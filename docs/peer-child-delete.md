# Peer Child SA deletion

Owner `lilyzhaun`, branch `fix/peer-child-delete-20261012`, base `a204c09`.
Scope: protected ESP Delete direction, paired response, terminal cause and
existing Connect-owned cleanup. No device operations in this repository.

RFC 7296 section 1.4.1 identifies the sender's inbound SPI: that is our
outbound SPI. The response carries our paired inbound SPI. This consumer
supports one active Child pair; deletion of that pair must retire the
session so that the existing owned kernel/network cleanup completes before
the consumer reconnects. A failed response cannot keep a deleted pair live.
Unknown or local-inbound SPIs cannot mutate another pair. Retired Child
generation handling and peer Child rekey belong to the next slice.

Validation: independent standard-library response decryption first failed
for both successful/failed sends, and a wrong-direction SPI incorrectly
changed the receive map (RED). Correct paired response followed by session
cancellation, unknown/wrong-direction preservation, exact Delete framing,
and cleanup-error ownership now pass. Full low-parallel race/shuffle and
vet passed. The final active pair is retired through Connect-owned cleanup;
the handler does not discard ownership metadata before cleanup succeeds.
While a local rekey owns the mutex, the receiver defers a Child Delete for
peer retransmission rather than blocking reception of that rekey's response.
No claim of carrier-originated deletion, actual-kernel cleanup from the
synthetic unit tests, or complete simultaneous Child rekey handling.
Original MIT code/RFC text only. Consumer lifecycle/fixed-pin/device pending.
