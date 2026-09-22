package driver

import (
	"net"
	"os"
	"reflect"
	"testing"

	"github.com/iniwex5/netlink"
)

const (
	ruleOwnerA            = 41001
	ruleOwnerB            = 41002
	ruleCanarySameSource  = 41003
	ruleCanaryOtherSource = 41004
)

var ruleOwnerNetworks = []struct {
	name   string
	family int
	source string
	other  string
}{
	{name: "v4", family: netlink.FAMILY_V4, source: "192.0.2.10/32", other: "192.0.2.20/32"},
	{name: "v6", family: netlink.FAMILY_V6, source: "2001:db8:1::10/128", other: "2001:db8:1::20/128"},
}

func TestAddRuleKernelPreservesPeerWhenSourceShared(t *testing.T) {
	for _, network := range ruleOwnerNetworks {
		for _, order := range []struct {
			name          string
			first, second int
		}{{"AB", ruleOwnerA, ruleOwnerB}, {"BA", ruleOwnerB, ruleOwnerA}} {
			t.Run(network.name+"/"+order.name, func(t *testing.T) {
				ruleOwnerFixture(t, network.family)
				tools := &NetTools{}
				mustXFRM(t, tools.AddRule(network.source, order.first))
				seedRuleOwner(t, network.source, ruleCanarySameSource)
				seedRuleOwner(t, network.other, ruleCanaryOtherSource)
				seedRuleOwner(t, network.other, order.second)
				before := rulesOutsideTarget(t, network.family, order.second, network.source)

				mustXFRM(t, tools.AddRule(network.source, order.second))

				assertSingleSourceOwner(t, network.family, order.first, network.source)
				assertSingleSourceOwner(t, network.family, order.second, network.source)
				if after := rulesOutsideTarget(t, network.family, order.second, network.source); !reflect.DeepEqual(before, after) {
					t.Errorf("AddRule changed foreign source/table rules: before=%d after=%d", len(before), len(after))
				}
			})
		}
	}
}

func TestAddRuleKernelRepeatKeepsOwnedSingletonAndPeers(t *testing.T) {
	for _, network := range ruleOwnerNetworks {
		for _, owner := range []struct {
			name  string
			table int
		}{{"A", ruleOwnerA}, {"B", ruleOwnerB}} {
			t.Run(network.name+"/"+owner.name, func(t *testing.T) {
				ruleOwnerFixture(t, network.family)
				for _, table := range []int{ruleOwnerA, ruleOwnerB, ruleCanarySameSource} {
					seedRuleOwner(t, network.source, table)
				}
				seedRuleOwner(t, network.other, ruleCanaryOtherSource)
				seedRuleOwner(t, network.other, owner.table)
				before := rulesOutsideTarget(t, network.family, owner.table, network.source)

				for range 3 {
					mustXFRM(t, (&NetTools{}).AddRule(network.source, owner.table))
				}

				assertSingleSourceOwner(t, network.family, owner.table, network.source)
				if after := rulesOutsideTarget(t, network.family, owner.table, network.source); !reflect.DeepEqual(before, after) {
					t.Errorf("repeated owned add changed peer/canary: before=%d after=%d", len(before), len(after))
				}
			})
		}
	}
}

func TestAddRuleKernelStopAKeepsBAndCanaries(t *testing.T) {
	for _, network := range ruleOwnerNetworks {
		t.Run(network.name, func(t *testing.T) {
			ruleOwnerFixture(t, network.family)
			for _, table := range []int{ruleOwnerA, ruleOwnerB, ruleCanarySameSource} {
				seedRuleOwner(t, network.source, table)
			}
			seedRuleOwner(t, network.other, ruleCanaryOtherSource)
			before := rulesOutsideTarget(t, network.family, ruleOwnerA, network.source)

			mustXFRM(t, (&NetTools{}).FlushRules(ruleOwnerA, "swuowna"))

			rules, err := netlink.RuleList(network.family)
			mustXFRM(t, err)
			for _, rule := range rules {
				if rule.Table == ruleOwnerA {
					t.Error("stopped A retained own rule")
				}
			}
			assertSingleSourceOwner(t, network.family, ruleOwnerB, network.source)
			if after := rulesOutsideTarget(t, network.family, ruleOwnerA, network.source); !reflect.DeepEqual(before, after) {
				t.Error("production FlushRules(A) changed B/canary")
			}
			t.Log("production FlushRules(A): A=0, B=1, same-source and different-source canaries unchanged")
		})
	}
}

func ruleOwnerFixture(t *testing.T, family int) {
	t.Helper()
	if os.Getenv("SOFTVOWIFI_REQUIRE_NETNS") == "1" && os.Getenv("ISSUE33_KERNEL_TEST") != "1" {
		t.Fatal("required isolated kernel marker missing")
	}
	isolatedKernel(t)
	baseline, err := netlink.RuleList(family)
	mustXFRM(t, err)
	t.Cleanup(func() {
		rules, err := netlink.RuleList(family)
		if err != nil {
			t.Error(err)
			return
		}
		for _, rule := range rules {
			switch rule.Table {
			case ruleOwnerA, ruleOwnerB, ruleCanarySameSource, ruleCanaryOtherSource:
				if err := netlink.RuleDel(&rule); err != nil {
					t.Error(err)
				}
			}
		}
		after, err := netlink.RuleList(family)
		if err != nil || !reflect.DeepEqual(baseline, after) {
			t.Errorf("owned rule cleanup did not restore child baseline: %v", err)
		}
		t.Log("owned rules removed; child baseline restored")
	})
}

func seedRuleOwner(t *testing.T, source string, table int) {
	t.Helper()
	_, prefix, err := net.ParseCIDR(source)
	mustXFRM(t, err)
	rule := netlink.NewRule()
	rule.Src, rule.Table, rule.Family = prefix, table, netlink.FAMILY_V4
	if prefix.IP.To4() == nil {
		rule.Family = netlink.FAMILY_V6
	}
	mustXFRM(t, netlink.RuleAdd(rule))
}

func rulesOutsideTarget(t *testing.T, family, table int, source string) []netlink.Rule {
	t.Helper()
	rules, err := netlink.RuleList(family)
	mustXFRM(t, err)
	var outside []netlink.Rule
	for _, rule := range rules {
		if rule.Table == table && rule.Src != nil && rule.Src.String() == source {
			continue
		}
		outside = append(outside, rule)
	}
	return outside
}

func assertSingleSourceOwner(t *testing.T, family, table int, source string) {
	t.Helper()
	rules, err := netlink.RuleList(family)
	mustXFRM(t, err)
	count := 0
	for _, rule := range rules {
		if rule.Table == table && rule.Src != nil && rule.Src.String() == source {
			count++
		}
	}
	if count != 1 {
		t.Errorf("source owner table=%d count=%d want=1", table, count)
	}
}
