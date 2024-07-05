package fuzz_firewall

import (
	"net"
	"time"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/test"
)

func FuzzFirewall_AddRule(data []byte) int {
	fdata := fuzz.NewConsumer(data)
	l := test.NewLogger()
	c := &cert.NebulaCertificate{}
	group, _ := fdata.GetString()
	ips, _ := fdata.GetString()
	localIps, _ := fdata.GetString()
	incoming, _ := fdata.GetBool()
	proto, _ := fdata.GetByte()
	startPort, _ := fdata.GetInt()
	startPort32 := int32(startPort)
	endPort, _ := fdata.GetInt()
	endPort32 := int32(endPort)
	host, _ := fdata.GetString()
	caName, _ := fdata.GetString()
	caSha, _ := fdata.GetString()
	groups := []string{group}
	_, ip, err := net.ParseCIDR(ips)
	if err != nil {
		return 0
	}
	_, localIp, err := net.ParseCIDR(localIps)
	if err != nil {
		return 0
	}
	fw := nebula.NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	fw.AddRule(incoming, proto, startPort32, endPort32, groups, host, ip, localIp, caName, caSha)
	return 0
}
