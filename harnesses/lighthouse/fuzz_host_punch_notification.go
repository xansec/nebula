package fuzz_lighthouse

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/header"
)

type mockEncWriter struct {
}

func (mw *mockEncWriter) SendMessageToVpnIp(t header.MessageType, st header.MessageSubType, vpnIp netip.Addr, p, nb, out []byte) {
	return
}

func (mw *mockEncWriter) SendVia(via *nebula.HostInfo, relay *nebula.Relay, ad, nb, out []byte, nocopy bool) {
	return
}

func (mw *mockEncWriter) SendMessageToHostInfo(t header.MessageType, st header.MessageSubType, hostinfo *nebula.HostInfo, p, nb, out []byte) {
	return
}

func (mw *mockEncWriter) Handshake(vpnIP netip.Addr) {}

func DeepCopy(src, dst interface{}) error {
	b, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dst)
}

func FuzzHostPunchNotification(data []byte) int {
	fdata := fuzz.NewConsumer(data)
	var n *nebula.NebulaMeta
	var vpnIp netip.Addr
	var w nebula.EncWriter
	n = &nebula.NebulaMeta{}
	fdata.GenerateStruct(n)
	if n.GetDetails() == nil || n.Details.Ip4AndPorts == nil || n.Details.Ip6AndPorts == nil {
		return 0
	}
	vpnIp = netip.MustParseAddr("192.0.1.1")
	w = &mockEncWriter{}

	var nOrig nebula.NebulaMeta
	if err := DeepCopy(n, &nOrig); err != nil {
		panic(err)
	}
	lhh := nebula.LightHouseHandler{}
	lhh.HandleHostPunchNotificationWrapper(n, vpnIp, w)

	if n.GetDetails() == nil {
		panic("Details is nil")
	}
	if n.Details.Ip4AndPorts != nil {
		for i := range nOrig.Details.Ip4AndPorts {
			if !reflect.DeepEqual(nOrig.Details.Ip4AndPorts[i], n.Details.Ip4AndPorts[i]) {
				panic(fmt.Sprintf("Ip4AndPorts not equal at index %d: %v != %v", i, nOrig.Details.Ip4AndPorts[i], n.Details.Ip4AndPorts[i]))
			}
		}
	}
	if n.Details.Ip6AndPorts != nil {
		for i := range nOrig.Details.Ip6AndPorts {
			if !reflect.DeepEqual(nOrig.Details.Ip6AndPorts[i], n.Details.Ip6AndPorts[i]) {
				panic(fmt.Sprintf("Ip6AndPorts not equal at index %d: %v != %v", i, nOrig.Details.Ip6AndPorts[i], n.Details.Ip6AndPorts[i]))
			}
		}
	}

	return 0
}
