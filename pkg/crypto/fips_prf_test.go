package crypto

import (
	"encoding/hex"
	"testing"
)

func Test_FIPS1862_matchesPublished160Bytes_whenRFC4186A5MK(t *testing.T) {
	mk, err := hex.DecodeString("e576d5ca332e9930018bf1baee2763c795b3c712")
	if err != nil {
		t.Fatal(err)
	}
	want := "536e5ebc4465582aa6a8ec9986ebb62025af1942efcbf4bc72b3943421f2a974" +
		"39d45aeaf4e30601983e972b6cfd46d1c363773365690d09cd44976b525f47d3" +
		"a60a985e955c53b090b2e4b73719196a402542968fd14a888f46b9a7886e4488" +
		"5949eab0fff69d52315c6c634fd14a7f0d52023d56f79698fa6596abeed4f93f" +
		"bb48eb534d985414ceed0d9a8ed33c387c9dfdab92ffbdf240fcecf65a2c93b9"

	got := NewFIPS1862PRFSHA1(mk).Bytes(nil, 160)

	if hex.EncodeToString(got) != want {
		t.Fatal("PRF differs from RFC 4186 Appendix A.5 K_encr|K_aut|MSK|EMSK")
	}
}
