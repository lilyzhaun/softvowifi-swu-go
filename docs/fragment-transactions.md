# Authenticated IKE fragment transactions

## Scope and evidence

Base `dbe7579`, branch `fix/a03-fragment-transaction`. The baseline completed a
window request after its first authenticated SKF datagram, and reconstructed
payloads using the last arriving fragment's Next Payload value. Normal Connect
could consequently consume an empty EAP round. These are reproducible protocol
defects, not a claim that a particular carrier has sent fragmented traffic.

The initial direct/independent UDP matrix produced 29 FAIL events and 5 PASS;
after the fix the focused matrix (including IKE role transitions) has 52 PASS.
One complete low-parallel race/shuffle run has 819 PASS and 22 existing opt-in
kernel skips, no failures or race reports; vet and formatting pass. The private
consumer's factory-to-Connect UDP tests independently reproduce three failing
fragment layouts on the old pin. A maintained remote pin, canonical module and
new authorized device smoke remain separate integration gates.

## Receive and delivery

Only fragments passing the existing SA header, role, exact wire length,
CBC/HMAC or GCM integrity and padding checks enter assembly. Fragment 1 owns
the inner payload type; later fragments must carry No Next Payload. Every
complete inner chain is parsed and checked for exact closure before window,
endpoint or activity commit. Partial messages are never empty DPD/EAP rounds.

The private receive result carries parsed payloads to EAP/final AUTH,
INFORMATIONAL, Child/IKE rekey, resume and MOBIKE consumers. Consumers must not
decrypt the last fragment again. Raw test entry points remain wrappers around
the same authenticated decoder. The public TaskManager enqueue channel is
unchanged; Session owns the decoded result published at its completion boundary.
This is not a synthetic plaintext packet or a locally re-encrypted peer packet.

## Identity and bounds

- Assembly keys contain both SA SPIs, the key-object generation, I/R direction,
  exchange and MID; equal MIDs cannot mix generations, directions or exchanges.
- Existing local limits remain 255 fragments and 64 KiB of reassembled content.
  The RFC's fragment count fields are 16-bit; 255 is not a claimed RFC maximum.
  At most 16 incomplete sets are retained. At most 16 completed request replies
  (each at most 64 KiB) are cached, with oldest-reply eviction at capacity.
- A 30-second fixed lifetime conserves resources as permitted by RFC7383 2.6.
  Duplicate fragments cannot extend it. The existing receive loop expires idle
  state; no additional worker or timer service is introduced.
- Per RFC7383 2.6, a larger authenticated total restarts a PMTU probe, dropping
  all old fragments and the old first type. A smaller total is ignored; bad ICV
  never resets the probe. Identical buffered duplicates are ignored and
  conflicting duplicates are rejected without replacing the authentic data.
- Request completion (including an unfragmented reply), hard window timeout,
  stop, waiter timeout/cancellation, AUTH reset, shutdown, dispatcher exit and
  either IKE rekey role transition release the corresponding fragment state.
- Within the bounded completed-request cache, RFC7383 2.6.1 retransmits the
  existing protected response only for an authenticated fragment 1 replay;
  later replays neither resend nor re-execute request effects. No second
  endpoint/liveness or business commit is made.

## Independent tests and limits

The standard-library peer exercises CBC and GCM, both SA roles, ordered,
reordered and duplicate input, bad integrity/metadata/full chains, cross-SA and
direction/exchange isolation, PMTU restart, size/count/queue/expiry limits,
input ownership and cancellation. Production window/FIFO, encrypted control
requests, parsed waiters and whole-request retransmission are covered.

The existing complete UDP Identity/Challenge/Success/shared-key AUTH test keeps
all its independent MAC, original IDi, MSK and Child assertions and adds ordered
and reversed fragmented responses, including a final AUTH over 3 KiB. It is not
an encoder/decoder loopback and does not install kernel state or contact a SIM.

No algorithm, proposal, EAP semantics, identity or carrier branch changes.
Outbound MID allocation still has its separately tracked concurrency defect
(A04); this fix does not reread or reinterpret that contract. Whole-SA replay
windows, old-SA retention after rekey, certificate chains, precise kernel TS,
AKA', natural rekey and real carrier fragmentation are not certified here.

## Sources

Original maintained code and [RFC7383 2.5/2.6/2.6.1](https://www.rfc-editor.org/rfc/rfc7383),
with [RFC5282](https://www.rfc-editor.org/rfc/rfc5282) for authenticated SKF headers
and Pad Length. No external client implementation copied. Original MIT,
module path, copyright and unknown-upstream provenance remain unchanged.
