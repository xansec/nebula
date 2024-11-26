package fuzz_firewall

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
)

func FuzzNewFirewallFromConfig(data []byte) int {
	fdata := fuzz.NewConsumer(data)
	direction, _ := fdata.GetString()
	port, _ := fdata.GetInt()
	proto, _ := fdata.GetByte()
	host, _ := fdata.GetString()
	var c *dummyCert
	fdata.GenerateStruct(&c)

	l := test.NewLogger()
	conf := config.NewC(l)
	conf.Settings["firewall"] = map[interface{}]interface{}{direction: []interface{}{map[interface{}]interface{}{"port": port, "proto": proto, "host": host}}}
	nebula.NewFirewallFromConfig(l, c, conf)
	return 0
}
