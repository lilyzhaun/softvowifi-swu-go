package swu

import (
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func TestLocalChildSelectionBoundToActualRequest(t *testing.T) {
	for _, kind := range []string{"number", "protocol", "zero_spi", "reused_spi", "key_bits", "integrity", "missing_esn", "duplicate_sa", "duplicate_nonce", "short_nonce", "missing_ts", "changed_ts", "unoffered_ke"} {
		t.Run(kind, func(t *testing.T) {
			s, _ := childRekeySession(t)
			snap := snapshotChildRekey(s)
			kernel := newRekeyKernel()
			mutate := func(p []ikev2.Payload) []ikev2.Payload {
				proposal := p[0].(*ikev2.EncryptedPayloadSA).Proposals[0]
				switch kind {
				case "number":
					proposal.ProposalNum = 9
				case "protocol":
					proposal.ProtocolID = ikev2.ProtoIKE
				case "zero_spi":
					proposal.SPI = make([]byte, 4)
				case "reused_spi":
					proposal.SPI = []byte{0, 0, 0, 101}
				case "key_bits":
					proposal.Transforms[0].Attributes[0].Val = 256
				case "integrity":
					proposal.Transforms[1].ID = ikev2.AUTH_HMAC_SHA1_96
				case "missing_esn":
					proposal.Transforms = proposal.Transforms[:2]
				case "duplicate_sa":
					p = append(p, p[0])
				case "duplicate_nonce":
					p = append(p, p[1])
				case "short_nonce":
					p[1].(*ikev2.EncryptedPayloadNonce).NonceData = []byte{1}
				case "missing_ts":
					p = p[:2]
				case "changed_ts":
					p[2].(*ikev2.EncryptedPayloadTS).TrafficSelectors = []*ikev2.TrafficSelector{ikev2.NewTrafficSelectorIPV4([]byte{192, 0, 2, 1}, []byte{192, 0, 2, 1}, 500, 500)}
				case "unoffered_ke":
					p = append(p, &ikev2.EncryptedPayloadKE{DHGroup: 14, KEData: make([]byte, 256)})
				}
				return p
			}
			if err := exerciseChildRekey(t, s, func() error { return s.rekeyChildSA(kernel) }, mutate); err == nil {
				t.Fatal("unoffered/incomplete response accepted")
			}
			snap.assertUncommitted(t, s)
			if len(kernel.calls) != 0 {
				t.Fatal("invalid selection reached kernel")
			}
		})
	}
}
