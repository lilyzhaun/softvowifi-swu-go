# Authentication lifetime and fresh authentication

Owner `lilyzhaun`, branch `fix/auth-lifetime-reauth-20261012`, base `152c560`.
Scope: authenticated final/INFORMATIONAL AUTH_LIFETIME, independent deadline
and typed one-shot retirement through existing Connect cleanup. Consumer
fresh-session admission/throttling belongs to its matching task. No device
operations in this repository.

RFC4478 sections2/3/5: lifetime is measured from receipt, remains applicable
after IKE rekey, zero requests immediate Initial exchange, and a new protected
INFORMATIONAL may update policy. It is not either key lifetime. Local earlier
reauth policy remains effective. Retirement is break-before-make and interrupts
active calls; make-before-break is not claimed. Extremely short repeated
reauthentication must be rate-limited by the consumer after old-SA cleanup,
without extending the expired SA or treating planned renewal as network failure.

Implementation: a receipt-based deadline with 20%/at-most-one-minute margin
is independent of key rotation; a protected zero notification triggers after
its reply attempt. Duplicated/older same-generation MIDs cannot renew a
relative deadline. Later authenticated policy may update it without defeating
earlier local policy. Connect returns a typed, ErrReauth-compatible terminal
cause after cleanup, never loops on its canceled Session. Break-before-make
retirement also retires ongoing IMS/calls through the consumer's normal path.

Validation: runtime zero/malformed and full independent Connect four-second
deadline were RED, then focused GREEN. The initial new Connect exposed the
legacy library-internal ErrReauth reuse loop; it now returns ownership to the
consumer. Receipt-aged one-hour deadline survives a real peer IKE rekey,
policy update/replay/local precedence and invalid-ICV behavior are covered.
An initial test used testing/synctest (Go1.25) and failed the Go1.24 module's
vet compatibility; it was replaced with bounded real timers and an earlier
receipt timestamp, retaining the behavioral assertions and module version.
Final full low-parallel race/shuffle and vet passed. Original MIT code/RFC text only; device natural
lifetime and carrier evidence remain separate.
