# EAP-AKA temporary identity and re-authentication lifecycle

This implementation covers the actual RFC 4187 EAP consumer, protected
temporary identities, fresh re-authentication keys, counter handling and
authenticated publication/retirement. Caller persistence and device
interoperability require their own evidence.

## Private caller contract

`Config.TemporaryIdentity` supplies a private `AKATemporaryIdentity` snapshot.
It supersedes the legacy `FastReauth*` fields. The Session captures independent
key slices and keeps the Config caller-owned, including callbacks installed
after `NewSession`.

- `Counter` is the **last successfully used value**, zero following full
  authentication. The next accepted fast counter must be strictly greater.
- `Pseudonym` is a UTF-8 username, not a complete NAI. The current home realm
  is appended when it is selected. `ReauthID` is the server-provided fast
  identity and is used exactly as received.
- Bind storage to the subscriber and authentication scope, and serialize
  owners. The library does not implement a filesystem or global shared cache.
- `OnTemporaryIdentityUpdate` is synchronous. Before a fast identity appears
  in AUTH1/Identity, its stored replacement contains only the retained
  pseudonym. Complete that retirement atomically before returning success.
  A restored new-API fast identity without this callback is rejected.
- Replacements are staged until the final responder IKE AUTH, Child-SA
  validation and applicable dataplane setup succeed. Errors, cancellation,
  EAP failure and protected Notification failure do not publish replacements.
- The callback receives its own copy. Errors become the fixed
  `ErrTemporaryIdentityStorage`, without exposing private paths or identifiers.
  Do not return success before a required persistent update has completed.
- The type's default JSON and string formatting omit identity/key contents.
  Do not deliberately serialize or reflect it into user configuration, logs
  or public snapshots. Use a separately controlled private storage format.

Legacy `OnFastReauthUpdate` cannot report storage failure or represent a
nonzero counter. It is deprecated; only full-auth counter-zero replacements
can be delivered through it, and fast-auth completion clears it. Legacy
restored identities also require at least one update callback before exposure.
New consumers should use the error-bearing callback exclusively.

## Protocol behavior

Integrity is verified before encrypted identity attributes are interpreted.
The explicit full-Challenge MAC-bypass diagnostic mode ignores encrypted
identity contents and does not publish authenticated identity state; fast
reauthentication always verifies the MAC regardless of that flag.

Counter/NONCE_S and next identities must be in AT_ENCR_DATA with AT_IV.
Duplicate or misplaced attributes, unknown required attributes, invalid
lengths and invalid padding are rejected. Counter-too-small replies keep the
counter and marker encrypted, authenticate the response together with NONCE_S,
and allow the server to continue full authentication in the same exchange.
As required by section 5.5, next-identity **contents** are ignored in that
fallback while container/TLV validation remains active.

Fast authentication uses the actually selected fast identity in
`SHA1(Identity | counter | NONCE_S | MK)` and takes the new MSK from the
beginning of the PRF stream. K_aut/K_encr remain those of full authentication.
Missing next identities or counter exhaustion retire fast state; a reused
one-time username is rejected. Exact retransmissions return independent
copies of the same response without repeating SIM work or publication.

## Sources and validation

The first regressions independently encode AES-CBC protected attributes and
HMAC-SHA1-128, verify protected counter responses and reject unencrypted
counter/nonce inputs. Fresh MSK vectors use the RFC 4187 section 7 input order;
their independent PRF was calibrated against all 160 published bytes in
[RFC 4186 Appendix A.5](https://www.rfc-editor.org/rfc/rfc4186#appendix-A.5).
Additional independent UDP peers exercise normal `Connect`, both final AUTHs,
cross-Session full/fast/pseudonym paths, missing-next retirement, protected
fallback, failed/cancelled exchanges and the authenticated CK|IK compatibility
branch. All values are synthetic. Real carrier fast-auth issuance, actual
consumer storage, device integration and long-running acceptance remain
separate validation layers. AKA-prime fast authentication remains unsupported.

Initial full local race/shuffle/count=1 validation passed 477 parent and 910
subtests, with 27 existing opt-in kernel/namespace skips. Following review
corrections, the affected SWu package passed 378 parent and 806 subtests, with
three existing kernel skips; full vet passed. Unchanged package evidence is
reused rather than represented as re-executed. Earlier failed regressions and
fixture compilation failures were retained in the validation record.

References: [RFC 4187](https://www.rfc-editor.org/rfc/rfc4187), especially
sections 4.1.1.8–9, 5, 7, 9.7–8 and 10.10–12. Only protocol semantics and
published test vectors are referenced; no external implementation, carrier
defaults or OEM parameters are copied. Existing module paths, dependencies,
copyright and license provenance are unchanged.
