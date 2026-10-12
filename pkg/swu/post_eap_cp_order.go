package swu

import "github.com/1239t/swu-go/pkg/ikev2"

// finalChildPayloadOrder tolerates a sender placing its unique CP after SA
// (contrary to RFC 7296 section 2.19) at the protected post-EAP ingress only.
// It changes neither values nor the authenticated wire/transcript. The strict
// validator still rejects missing/duplicate CP or SA and all invalid content.
func finalChildPayloadOrder(payloads []ikev2.Payload) []ikev2.Payload {
	cp, sa := -1, -1
	for index, payload := range payloads {
		switch payload.(type) {
		case *ikev2.EncryptedPayloadCP:
			if cp >= 0 {
				return payloads
			}
			cp = index
		case *ikev2.EncryptedPayloadSA:
			if sa >= 0 {
				return payloads
			}
			sa = index
		}
	}
	if sa < 0 || cp <= sa {
		return payloads
	}
	ordered := append([]ikev2.Payload(nil), payloads...)
	copy(ordered[sa+1:cp+1], payloads[sa:cp])
	ordered[sa] = payloads[cp]
	return ordered
}
