package driver

import (
	"reflect"
	"testing"

	"github.com/iniwex5/netlink"
)

func TestSourceRuleKernelExplicitPriorityPreservesEarlierOwnerRules(t *testing.T) {
	for _, network := range ruleOwnerNetworks {
		t.Run(network.name, func(t *testing.T) {
			ruleOwnerFixture(t, network.family)
			peer := netlink.NewRule()
			mask := uint32(0xfff00000)
			peer.Family, peer.Priority, peer.Table, peer.Mark, peer.Mask = network.family, 9000, ruleOwnerB, 0x3600000, &mask
			mustXFRM(t, netlink.RuleAdd(peer))
			before := rulesOutsideTarget(t, network.family, ruleOwnerA, network.source)
			tools := NewNetTools()
			tools.SourceRulePriority = 9001
			for range 2 {
				mustXFRM(t, tools.AddRule(network.source, ruleOwnerA))
				rules, err := netlink.RuleList(network.family)
				mustXFRM(t, err)
				found := false
				for _, rule := range rules {
					if rule.Table == ruleOwnerA {
						found = true
						if rule.Priority != 9001 {
							t.Errorf("source rule priority=%d want 9001 after owner rule 9000", rule.Priority)
						}
					}
				}
				if !found {
					t.Fatal("source rule missing")
				}
			}
			if after := rulesOutsideTarget(t, network.family, ruleOwnerA, network.source); !reflect.DeepEqual(before, after) {
				t.Fatal("source installation changed another owner's rule")
			}
		})
	}
}
