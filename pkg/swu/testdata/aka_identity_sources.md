# EAP-AKA Identity Test Sources

- RFC 4187 sections 4.1.5, 7, 9.1, 10.5, 10.13:
  https://www.rfc-editor.org/rfc/rfc4187.html
- AOSP IPsec, Android 16 tag `android-16.0.0_r1`, commit
  `fb5af75126a170f44c074d0cbd4eb7e2ac7ddfe0`, Apache-2.0:
  https://android.googlesource.com/platform/packages/modules/IPsec/+/fb5af75126a170f44c074d0cbd4eb7e2ac7ddfe0/tests/iketests/src/java/com/android/internal/net/eap/EapAkaTest.java
- State and identity selection reference (independently implemented in Go):
  https://android.googlesource.com/platform/packages/modules/IPsec/+/fb5af75126a170f44c074d0cbd4eb7e2ac7ddfe0/src/java/com/android/internal/net/eap/statemachine/EapAkaMethodStateMachine.java

The tests reuse public RAND/AUTN, RES/CK/IK, request/response bytes and key
vectors from AOSP. They do not contain subscriber captures or copied Java
implementation. AOSP's Identity vector uses the username `0` plus IMSI,
whereas this SWu implementation retains its existing full 3GPP NAI.
Consequently, the Identity-to-Challenge test independently rebinds the
public challenge and response MACs to that NAI using the existing test-only
RFC Appendix A expansion, not the production PRF. This is not a claim that
the original bare-username AOSP Identity response is emitted in production.
The direct-Challenge outer-identity test matches the unmodified official
request, response and K_aut exactly; the independent expansion also matches
the official bare-username K_aut and MSK exactly. No MAC-validation bypass
is enabled in these Identity tests.

This bounded slice always chooses permanent identity, including ANY_ID_REQ.
RFC 4187 section 4.1.5 permits a peer not to select fast reauthentication.
It does not invent or persist pseudonyms. Permanent selection invalidates
the current session's fast cache and prevents reloading its old configured
identity into subsequent AUTH1 packets; the caller's Config is not mutated.
The three-round limit and ordering come from RFC 4187 sections 4.1.5/9.1;
the preexisting outer EAP loop has no round counter.

CHECKCODE is checked on every Type23 Challenge and Reauthentication request,
including zero Identity exchanges. In that case only an absent attribute or
an empty checkcode is valid; a digest, invalid length or duplicate is rejected
before SIM authentication, key/cache mutation or callbacks. For Identity
exchanges the hash uses actual request/response pairs with reserved/padding
bytes intact; identical retransmissions are included once.

Local policy requires CHECKCODE after any skippable Identity extension.
RFC 4187 section 10.13 requires the server to include it when extending its
Identity request; the peer's normative requirement to enforce presence is
conditional on implementing extension processing. An unknown skipped
attribute alone is not described here as an unconditional client MUST.
No outbound CHECKCODE is required because responses add only AT_IDENTITY.
Type50 behavior is unchanged; a Type50 switch after Type23 Identity is
explicitly unsupported.

RFC 7296 sections 2.15/2.16:
https://www.rfc-editor.org/rfc/rfc7296.html#section-2.15
The initiator AUTH uses the original AUTH1 IDi body (ID type, three reserved
bytes and identity data; no generic payload header). The session owns an
encoded copy, distinct from mutable outer Type1 or inner AKA identity;
attempt reset clears it and final AUTH cannot reconstruct a substitute NAI.
The UDP integration test continues through EAP Success and independently
verifies initiator AUTH using the original pseudonym IDi, rejects the
permanent-NAI alternative, then returns independent responder AUTH and
observes Child SA establishment before controlled context cancellation.
