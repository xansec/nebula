package fuzz_lighthouse

import (
	"context"
	"fmt"
	"log"
	"net/netip"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/test"
)

type mockEncWriter struct {
}

func (mw *mockEncWriter) SendMessageToVpnIp(t header.MessageType, st header.MessageSubType, vpnIp netip.Addr, p, nb, out []byte) {
}

func (mw *mockEncWriter) SendVia(via *nebula.HostInfo, relay *nebula.Relay, ad, nb, out []byte, nocopy bool) {
}

func (mw *mockEncWriter) SendMessageToHostInfo(t header.MessageType, st header.MessageSubType, hostinfo *nebula.HostInfo, p, nb, out []byte) {
}

func (mw *mockEncWriter) Handshake(vpnIP netip.Addr) {}

func FuzzHandleRequest(data []byte) int {
	l := test.NewLogger()
	myVpnNet := netip.MustParsePrefix("10.128.0.1/0")

	c := config.NewC(l)
	lh, err := nebula.NewLightHouseFromConfig(context.Background(), l, c, myVpnNet, nil, nil)
	if err != nil {
		log.Printf("Failed to create lighthouse: %v", err)
		return 0
	}

	var rAddr netip.AddrPort
	var vpnIp netip.Addr
	var p []byte
	var w nebula.EncWriter
	fdata := fuzz.NewConsumer(data)
	//fdata.GenerateStruct(&rAddr)
	rAddr = netip.AddrPortFrom(netip.MustParseAddr("192.0.1.1"), 4242)
	//fdata.GenerateStruct(&vpnIp)
	vpnIp = netip.MustParseAddr("128.20.1.2")
	//fdata.GenerateStruct(&w)
	w = &mockEncWriter{}
	fdata.GenerateStruct(&p)

	// Unmarshal the original meta
	var nCopy nebula.NebulaMeta
	if err := nCopy.Unmarshal(p); err != nil {
		log.Printf("Failed to unmarshal original data: %v", err)
		return 0
	}

	lhh := lh.NewRequestHandler()
	lhh.HandleRequest(rAddr, vpnIp, p, w)

	n := lhh.GetMeta()

	// Check for overflow
	for i, peer := range n.Details.Ip4AndPorts {
		if peer.Port != nCopy.Details.Ip4AndPorts[i].Port {
			panic(fmt.Sprintf("Possible port overflow for Ip4AndPort: original=%d, modified=%d", nCopy.Details.Ip4AndPorts[i].Port, peer.Port))
		}
	}

	for i, peer := range n.Details.Ip6AndPorts {
		if peer.Port != nCopy.Details.Ip6AndPorts[i].Port {
			panic(fmt.Sprintf("Possible port overflow for Ip6AndPort: original=%d, modified=%d", nCopy.Details.Ip6AndPorts[i].Port, peer.Port))
		}
	}

	return 0
}
