package fuzz_lighthouse

import (
	"fmt"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/slackhq/nebula"
)

func FuzzAddrPort(data []byte) int {
	fdata := fuzz.NewConsumer(data)
	var ipv4 *nebula.Ip4AndPort
	var ipv6 *nebula.Ip6AndPort
	fdata.GenerateStruct(&ipv4)
	fdata.GenerateStruct(&ipv6)
	if ipv4 == nil || ipv6 == nil {
		return 0
	}

	new_ipv4 := nebula.AddrPortFromIp4AndPort(ipv4)
	new_ipv6 := nebula.AddrPortFromIp6AndPort(ipv6)

	// if new_ipv4.Addr() != netip.IPv4Unspecified() {
	// 	panic("Invalid 0.0.0.0 used")
	// }
	if uint32(new_ipv4.Port()) != ipv4.GetPort() {
		panic(fmt.Sprintf("Potential overflow detected: %d != %d", new_ipv4.Port(), ipv4.GetPort()))
	}
	// if new_ipv6.Addr() != netip.IPv6Unspecified() {
	// 	panic("Invalid :: used")
	// }
	if uint32(new_ipv6.Port()) != ipv6.GetPort() {
		panic(fmt.Sprintf("Potential overflow detected: %d != %d", new_ipv6.Port(), ipv6.GetPort()))
	}

	return 0
}
