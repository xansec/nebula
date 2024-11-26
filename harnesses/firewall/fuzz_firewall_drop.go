package fuzz_firewall

import (
	"net"
	"net/netip"
	"time"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/test"
)

func FuzzFirewallDrop(data []byte) int {
	fdata := fuzz.NewConsumer(data)
	localIP, _ := fdata.GetNBytes(4)
	remoteIP, _ := fdata.GetNBytes(4)
	// localPort, _ := fdata.GetUint16()
	// remotePort, _ := fdata.GetUint16()
	// protocol, _ := fdata.GetByte()
	// fragment, _ := fdata.GetBool()
	// certName, _ := fdata.GetString()
	// certGroups, _ := fdata.GetString()
	// certIssuer, _ := fdata.GetString()
	netIP, _ := fdata.GetNBytes(4)
	netMask, _ := fdata.GetNBytes(4)

	if len(localIP) != 4 || len(remoteIP) != 4 || len(netIP) != 4 || len(netMask) != 4 {
		return 0
	}

	l := test.NewLogger()

	var p firewall.Packet
	fdata.GenerateStruct(&p)
	// p := firewall.Packet{
	// 	LocalIP:    iputil.Ip2VpnIp(net.IP(localIP)),
	// 	RemoteIP:   iputil.Ip2VpnIp(net.IP(remoteIP)),
	// 	LocalPort:  localPort,
	// 	RemotePort: remotePort,
	// 	Protocol:   protocol,
	// 	Fragment:   fragment,
	// }

	var ipNet net.IPNet
	fdata.GenerateStruct(&ipNet)
	// ipNet := net.IPNet{
	// 	IP:   net.IPv4(netIP[0], netIP[1], netIP[2], netIP[3]),
	// 	Mask: net.IPMask{netMask[0], netMask[1], netMask[2], netMask[3]},
	// }

	var c dummyCert
	fdata.GenerateStruct(&c)
	// c := cert.NebulaCertificate{
	// 	Details: cert.NebulaCertificateDetails{
	// 		Name:           certName,
	// 		Ips:            []*net.IPNet{&ipNet},
	// 		Groups:         []string{certGroups},
	// 		InvertedGroups: map[string]struct{}{certGroups: {}},
	// 		Issuer:         certIssuer,
	// 	},
	// }

	var h nebula.HostInfo
	fdata.GenerateStruct(&h)
	// h := nebula.HostInfo{
	// 	ConnectionState: &nebula.ConnectionState{
	// 		peerCert: &c,
	// 	},
	// 	vpnIp: iputil.Ip2VpnIp(ipNet.IP),
	// }
	// h.CreateRemoteCIDR(&c)

	h.CreateRemoteCIDR(&c)

	fw := nebula.NewFirewall(l, time.Second, time.Minute, time.Hour, &c)
	fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"default-group"}, "", netip.Prefix{}, netip.Prefix{}, "", "")

	cp := cert.NewCAPool()

	fw.Drop(p, false, &h, cp, nil)
	return 0
}
