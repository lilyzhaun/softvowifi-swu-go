# Final IKE_AUTH errors without a Child SA

Owner: `lilyzhaun`. Branch: `fix/ike-auth-reject`. Base: `6af42a9694debd2b50ea66deb6ea19ff4fe35679`.

RFC 7296 sections 1.2 and 3.15.4 allow address-assignment failure to be
reported without a Child SA. The final-response handler previously returned
`IKE AUTH incomplete` before inspecting the error Notify. Reuse the existing
typed reject parser on that failure path and give INTERNAL_ADDRESS_FAILURE
its explicit, data-free description.

This change only reports a rejection. It does not authenticate a peer,
publish a Child SA, apply status notifications, retry another address family,
or change proposals, CP requests, EAP, or successful responder AUTH validation.
All devices/operators use the same path. No external source code was copied;
the protocol reference is https://www.rfc-editor.org/rfc/rfc7296#section-3.15.4.
Existing MIT licensing and provenance remain unchanged.

Direct encrypted-response regression failed first for Notify 36/38/11011
and the address-error description, then passed after the minimal repair.
Tests also reject a corrupted integrity tag and preserve SA, transcript,
ticket and status state. The full library race/shuffle suite passed across
six tested packages; two packages have no tests. Existing opt-in kernel
tests are not evidence of device execution. This is an error-reporting fix,
not proof that an operator will allocate an address or provide IMS service.
