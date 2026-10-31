package swu

import (
	"errors"
	"reflect"
	"slices"
	"syscall"
	"testing"
)

func TestProposalPolicyPublicValidationIsSideEffectFree(t *testing.T) {
	for _, test := range []struct {
		name       string
		ike, child []string
		layout     string
		invalid    bool
	}{
		{name: "legacy-nil"},
		{name: "complete", ike: []string{policyIKE256}, child: []string{policyESP128}},
		{name: "closed-combined", ike: []string{policyIKE128, policyIKE256}, layout: "single-combined"},
		{name: "empty", ike: []string{}, invalid: true},
		{name: "unknown", child: []string{"unsupported"}, invalid: true},
		{name: "widening", ike: []string{policyIKE128, "ike-cbc256-sha384-prfsha384-dh14"}, layout: "single-combined", invalid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			opened := false
			cfg := &Config{IKEProposals: slices.Clone(test.ike), ESPProposals: slices.Clone(test.child), IKEProposalLayout: test.layout,
				SocketControl: func(string, string, syscall.RawConn) error { opened = true; return errors.New("unexpected socket") }}
			err := cfg.ValidateProposalPolicy()
			if test.invalid && !errors.Is(err, ErrInvalidProposalPolicy) || !test.invalid && err != nil {
				t.Fatal("public policy validation differs from the session compiler")
			}
			if opened || !reflect.DeepEqual(cfg.IKEProposals, test.ike) || !reflect.DeepEqual(cfg.ESPProposals, test.child) ||
				cfg.IKEProposalLayout != test.layout || cfg.IKEDHGroup != 0 || cfg.InitialIKEProposalNumber != 0 || cfg.InitialChildProposalNumber != 0 {
				t.Fatal("validation performed transport work or modified caller configuration")
			}
		})
	}
}
