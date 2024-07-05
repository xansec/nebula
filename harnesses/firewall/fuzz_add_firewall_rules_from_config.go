package fuzz_firewall

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
)

func FuzzAddFirewallRulesFromConfig(data []byte) int {
	fdata := fuzz.NewConsumer(data)
	direction, _ := fdata.GetString()
	port, _ := fdata.GetInt()
	proto, _ := fdata.GetByte()
	host, _ := fdata.GetString()
	l := test.NewLogger()
	conf := config.NewC(l)
	mf := &mockFirewall{}
	conf.Settings["firewall"] = map[interface{}]interface{}{direction: []interface{}{map[interface{}]interface{}{"port": port, "proto": proto, "host": host}}}
	nebula.AddFirewallRulesFromConfig(l, true, conf, mf)
	return 0
}
