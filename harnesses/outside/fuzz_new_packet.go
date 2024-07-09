package fuzz_outside

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/firewall"
)

func FuzzNewPacket(data []byte) int {
	fdata := fuzz.NewConsumer(data)
	// p := &firewall.Packet{}
	var p *firewall.Packet
	fdata.GenerateStruct(&p)
	incoming, _ := fdata.GetBool()
	fbytes, _ := fdata.GetBytes()

	_ = nebula.NewPacket(fbytes, incoming, p)

	return 0
}
