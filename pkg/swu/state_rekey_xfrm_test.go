package swu

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"testing"

	"github.com/1239t/swu-go/pkg/driver"
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/ipsec"
	"github.com/iniwex5/netlink"
	"go.uber.org/zap"
)

var errRekeyKernel = errors.New("synthetic kernel failure")
var errRekeyRollback = errors.New("synthetic rollback failure")

type rekeyKernel struct {
	calls        []string
	adds         []driver.XFRMSAConfig
	policies     []driver.XFRMSPConfig
	deletes      []driver.XFRMSAConfig
	live         map[uint32]bool
	fail         string
	rollbackFail bool
	before       func()
}

func newRekeyKernel() *rekeyKernel {
	return &rekeyKernel{live: map[uint32]bool{101: true, 102: true}}
}

func (kernel *rekeyKernel) record(call string) error {
	if kernel.before != nil {
		kernel.before()
	}
	kernel.calls = append(kernel.calls, call)
	if call == kernel.fail {
		return errRekeyKernel
	}
	return nil
}

func (kernel *rekeyKernel) AddSA(cfg driver.XFRMSAConfig) error {
	kernel.adds = append(kernel.adds, cfg)
	if err := kernel.record(fmt.Sprintf("add%d", len(kernel.adds))); err != nil {
		return err
	}
	kernel.live[cfg.SPI] = true
	return nil
}

func (kernel *rekeyKernel) DelSA(spi uint32, src, dst net.IP, proto netlink.Proto) error {
	kernel.deletes = append(kernel.deletes, driver.XFRMSAConfig{SPI: spi, Src: src, Dst: dst, Proto: proto})
	if err := kernel.record(fmt.Sprintf("del%d", spi)); err != nil {
		return err
	}
	if kernel.rollbackFail && spi != 101 && spi != 102 {
		return errRekeyRollback
	}
	delete(kernel.live, spi)
	return nil
}

func (kernel *rekeyKernel) AddSP(cfg driver.XFRMSPConfig) error {
	kernel.policies = append(kernel.policies, cfg)
	return kernel.record(fmt.Sprintf("sp%d", len(kernel.policies)))
}

func rekeyXFRMFixture() (*Session, childSARekey) {
	sess := NewSession(&Config{ReplayWindow: 128}, zap.NewNop())
	sess.xfrmLocalIP, sess.xfrmRemoteIP = net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")
	sess.xfrmLocalPort, sess.xfrmRemotePort = 4501, 4500
	sess.xfrmIfID, sess.childESN = 37, true
	sess.childIntegID = uint16(ikev2.AUTH_HMAC_SHA2_256_128)
	return sess, childSARekey{
		out:    &ipsec.SecurityAssociation{SPI: 201, EncryptionKey: []byte{1}, IntegrityKey: []byte{3}},
		in:     &ipsec.SecurityAssociation{SPI: 202, EncryptionKey: []byte{2}, IntegrityKey: []byte{4}},
		encrID: uint16(ikev2.ENCR_AES_CBC), keyBits: 128,
	}
}

func TestChildRekeyXFRMFailure(t *testing.T) {
	for _, test := range []struct {
		name  string
		calls []string
		live  map[uint32]bool
	}{
		{"add1", []string{"add1"}, map[uint32]bool{101: true, 102: true}},
		{"add2", []string{"add1", "add2", "del201"}, map[uint32]bool{101: true, 102: true}},
		{"sp1", []string{"add1", "add2", "sp1"}, map[uint32]bool{101: true, 102: true, 201: true, 202: true}},
		{"sp2", []string{"add1", "add2", "sp1", "sp2"}, map[uint32]bool{101: true, 102: true, 201: true, 202: true}},
		{"sp3", []string{"add1", "add2", "sp1", "sp2", "sp3"}, map[uint32]bool{101: true, 102: true, 201: true, 202: true}},
		{"sp4", []string{"add1", "add2", "sp1", "sp2", "sp3", "sp4"}, map[uint32]bool{101: true, 102: true, 201: true, 202: true}},
		{"del101", []string{"add1", "add2", "sp1", "sp2", "sp3", "sp4", "del101"}, map[uint32]bool{101: true, 102: true, 201: true, 202: true}},
		{"del102", []string{"add1", "add2", "sp1", "sp2", "sp3", "sp4", "del101", "del102"}, map[uint32]bool{102: true, 201: true, 202: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			sess, next := rekeyXFRMFixture()
			kernel := newRekeyKernel()
			kernel.fail = test.name

			err := sess.rekeyXFRM(kernel, next, [2]uint32{101, 102})

			if !errors.Is(err, errRekeyKernel) {
				t.Errorf("failure not propagated: %v", err)
			}
			if !reflect.DeepEqual(kernel.calls, test.calls) {
				t.Errorf("calls = %v, want %v", kernel.calls, test.calls)
			}
			if !reflect.DeepEqual(kernel.live, test.live) {
				t.Errorf("live SPI set = %v, want %v", kernel.live, test.live)
			}
		})
	}
}

func TestChildRekeyXFRMRollbackFailure(t *testing.T) {
	sess, next := rekeyXFRMFixture()
	kernel := newRekeyKernel()
	kernel.fail, kernel.rollbackFail = "add2", true

	err := sess.rekeyXFRM(kernel, next, [2]uint32{101, 102})

	if !errors.Is(err, errRekeyKernel) || !errors.Is(err, errRekeyRollback) {
		t.Fatalf("lost joined failure: %v", err)
	}
	if !reflect.DeepEqual(kernel.live, map[uint32]bool{101: true, 102: true, 201: true}) {
		t.Fatalf("unexpected residual states: %v", kernel.live)
	}
}

func TestChildRekeyXFRMMappingFailureBeforeMutation(t *testing.T) {
	for _, algorithm := range []string{"encryption", "integrity"} {
		t.Run(algorithm, func(t *testing.T) {
			sess, next := rekeyXFRMFixture()
			kernel := newRekeyKernel()
			switch algorithm {
			case "encryption":
				next.encrID = 65535
			case "integrity":
				sess.childIntegID = 65535
			}

			err := sess.rekeyXFRM(kernel, next, [2]uint32{101, 102})

			if err == nil || len(kernel.calls) != 0 {
				t.Fatalf("mapping error = %v, kernel calls = %v", err, kernel.calls)
			}
		})
	}
}

func TestChildRekeyXFRMSuccessPreservesConfiguration(t *testing.T) {
	for _, aead := range []bool{false, true} {
		t.Run(fmt.Sprintf("aead_%t", aead), func(t *testing.T) {
			sess, next := rekeyXFRMFixture()
			if aead {
				next.encrID = uint16(ikev2.ENCR_AES_GCM_16)
			}
			kernel := newRekeyKernel()
			out := driver.XFRMSAConfig{
				Src: sess.xfrmLocalIP, Dst: sess.xfrmRemoteIP, SPI: 201,
				Proto: netlink.XFRM_PROTO_ESP, Mode: netlink.XFRM_MODE_TUNNEL,
				EncapType: netlink.XFRM_ENCAP_ESPINUDP, EncapSrcPort: 4501, EncapDstPort: 4500,
				Ifid: 37, ReplayWindow: 128, SADir: netlink.XFRM_SA_DIR_OUT, ESN: true, IsAEAD: aead,
			}
			in := out
			in.Src, in.Dst, in.SPI = sess.xfrmRemoteIP, sess.xfrmLocalIP, 202
			in.EncapSrcPort, in.EncapDstPort, in.SADir = 4500, 4501, netlink.XFRM_SA_DIR_IN
			if aead {
				out.AeadAlgoName, in.AeadAlgoName = "rfc4106(gcm(aes))", "rfc4106(gcm(aes))"
				out.AeadICVLen, in.AeadICVLen = 128, 128
				out.AeadKey, in.AeadKey = []byte{1}, []byte{2}
			} else {
				out.CryptAlgoName, in.CryptAlgoName = "cbc(aes)", "cbc(aes)"
				out.CryptKey, in.CryptKey = []byte{1}, []byte{2}
				out.AuthAlgoName, in.AuthAlgoName = "hmac(sha256)", "hmac(sha256)"
				out.AuthKey, in.AuthKey = []byte{3}, []byte{4}
				out.AuthTruncLen, in.AuthTruncLen = 128, 128
			}
			var policies []driver.XFRMSPConfig
			for _, state := range []driver.XFRMSAConfig{out, in} {
				dir := netlink.XFRM_DIR_OUT
				if state.SPI == 202 {
					dir = netlink.XFRM_DIR_IN
				}
				for _, cidr := range []string{"0.0.0.0/0", "::/0"} {
					_, selector, err := net.ParseCIDR(cidr)
					if err != nil {
						t.Fatal(err)
					}
					policies = append(policies, driver.XFRMSPConfig{
						Src: selector, Dst: selector, Dir: dir, Priority: driver.OuterBroadPolicyPriority,
						TmplSrc: state.Src, TmplDst: state.Dst, TmplProto: netlink.XFRM_PROTO_ESP,
						TmplMode: netlink.XFRM_MODE_TUNNEL, TmplSPI: int(state.SPI), Ifid: 37,
					})
				}
			}

			err := sess.rekeyXFRM(kernel, next, [2]uint32{101, 102})

			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(kernel.calls, []string{"add1", "add2", "sp1", "sp2", "sp3", "sp4", "del101", "del102"}) {
				t.Errorf("calls = %v", kernel.calls)
			}
			if !reflect.DeepEqual(kernel.adds, []driver.XFRMSAConfig{out, in}) {
				t.Error("SA configuration changed")
			}
			for index, policy := range kernel.policies {
				want := policies[index]
				if !policy.Src.IP.Equal(want.Src.IP) {
					t.Fatal("selector IP changed")
				}
				want.Src.IP, want.Dst.IP = policy.Src.IP, policy.Dst.IP
				if !reflect.DeepEqual(policy, want) {
					t.Errorf("SP %d settings changed", index)
				}
			}
			wantDeletes := []driver.XFRMSAConfig{
				{SPI: 101, Src: sess.xfrmLocalIP, Dst: sess.xfrmRemoteIP, Proto: netlink.XFRM_PROTO_ESP},
				{SPI: 102, Src: sess.xfrmRemoteIP, Dst: sess.xfrmLocalIP, Proto: netlink.XFRM_PROTO_ESP},
			}
			if !reflect.DeepEqual(kernel.deletes, wantDeletes) || !reflect.DeepEqual(kernel.live, map[uint32]bool{201: true, 202: true}) {
				t.Error("incorrect old SA retirement")
			}
		})
	}
}
