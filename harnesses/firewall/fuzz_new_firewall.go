package fuzz_firewall

import (
	"time"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/test"
)

func FuzzNewFirewall(data []byte) int {
	fdata := fuzz.NewConsumer(data)
	tcpTimeout, _ := fdata.GetUint64()
	udpTimeout, _ := fdata.GetUint64()
	defaultTimeout, _ := fdata.GetUint64()

	if tcpTimeout == 0 || udpTimeout == 0 || defaultTimeout == 0 {
		return 0
	}

	var c *dummyCert
	fdata.GenerateStruct(&c)
	l := test.NewLogger()
	tcpTimeoutDuration := time.Duration(tcpTimeout)
	udpTimeoutDuration := time.Duration(udpTimeout)
	defaultTimeoutDuration := time.Duration(defaultTimeout)
	nebula.NewFirewall(l, tcpTimeoutDuration, udpTimeoutDuration, defaultTimeoutDuration, c)
	return 0
}
