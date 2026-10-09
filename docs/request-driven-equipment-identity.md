# Request-driven equipment identity

Owner: `lilyzhaun`; branch: `fix/request-driven-device-identity`.
Base: `5d5d4539c31e1dc05af499e715782cc0206dfb2a`.

TS 24.302 section 7.2.6 describes replying to a DEVICE_IDENTITY request,
not unconditionally attaching equipment identity to the initial IKE_AUTH.
Connect now uses the shared standard initial builder and retains cfg.IMEI
for the existing requested-response path. Replies retain the request's
legacy/private Notify code. No carrier, host, CP, APN, proposal or security
downgrade condition is introduced.

Reference: ETSI TS 124 302 V17.5.0 (2022-07), sections 7.2.6/8.2.9.2,
https://www.etsi.org/deliver/etsi_ts/124300_124399/124302/17.05.00_60/ts_124302v170500p.pdf .
Only protocol behavior was compared with fasferraz/SWu-IKEv2
bf5d258b7298db65e64b43065b153325eba47a9e (GPL-3.0); no GPL code was copied
or run with real subscriber material. Existing MIT/provenance is unchanged.

The real UDP Connect regression first failed because AUTH1 contained an
unsolicited identity. After the initial-builder repair, the private-code
reply check exposed the pre-existing alias mismatch (41101 request answered
with 16432); preserving the requested code fixes both cases. The independent
AKA wire bytes/MAC, one SIM invocation, terminal failure, privacy checks and
explicit legacy encoding goldens remain tested. Initial messages are exactly
the original eight payloads even with configured IMEI; requested replies are
exactly compared after a verified synthetic AKA challenge. Full six-package
race/shuffle and vet passed; two packages have no tests.

The preceding device-only diagnostic removed just the proactive Notify and
reached a real authenticated Child SA with addresses and P-CSCF, where the
original same-endpoint request returned INTERNAL_ADDRESS_FAILURE. IMS then
returned 403 on legacy identity; tunnel establishment and IMS registration
are distinct gates. Production pin/build/device verification is recorded by
the consuming project. Co-carried EAP/identity-request handling and full
peer-certificate authentication are not expanded or claimed by this change.
