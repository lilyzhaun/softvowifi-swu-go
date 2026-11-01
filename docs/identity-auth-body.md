# Received identity bytes and IKE AUTH

RFC 7296 sections 2.15 and 3.5 define `IDi'` / `IDr'` as the entire ID
payload body, excluding the generic payload header. The three RESERVED bytes
have no identity semantics, but remain part of the bytes authenticated by AUTH.
Ignoring their meaning on receipt does not mean replacing them with zeros before
computing the MAC.

`DecodePayloadID` retains an owned copy of the received body.
`EncryptedPayloadID.AuthenticationBody()` returns a separate copy of that
transcript, independent of the input buffer and mutable decoded fields. For
locally constructed payloads it returns their normal encoding. `Encode()` still
uses the current fields and sends zero RESERVED bytes as required by the RFC.

The responder AUTH path uses this body for both the IDr captured during EAP and
an IDr in the final protected response. Existing within-attempt IDr consistency,
single AUTH, method/MSK/transcript checks and transactional Child-SA commit remain
in effect. This does not add a caller-selected identity policy or certificate
trust validation.

Direct regressions use independently supplied IDr bytes, standard-library
CBC/HMAC protection and an independent AUTH oracle. They cover final/cached/
repeated IDr, zero-byte compatibility, normalized-MAC rejection, and normal UDP
Connect with both SK and SKF delivery. Before the fix, six behavior cases failed
and the zero-byte control passed. Decoder ownership and outgoing-zero tests also
cover the new API. Actual final test/CI results are recorded in the fixing PR;
these synthetic peers do not establish carrier, SIM or device interoperability.

Only RFC 7296 (October 2014; IETF Trust Legal Provisions), the existing maintained
implementation and Go standard-library APIs were consulted. No external client
code, configuration format or operator parameters were copied.
