package fuzz_firewall

import (
	"time"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/test"
)

func FuzzNewFirewall(data []byte) int {
	fdata := fuzz.NewConsumer(data)
	tcpTimeout, _ := fdata.GetInt()
	udpTimeout, _ := fdata.GetInt()
	defaultTimeout, _ := fdata.GetInt()

	var c *cert.NebulaCertificate
	fdata.GenerateStruct(&c)
	l := test.NewLogger()
	tcpTimeoutDuration := time.Duration(tcpTimeout)
	udpTimeoutDuration := time.Duration(udpTimeout)
	defaultTimeoutDuration := time.Duration(defaultTimeout)
	nebula.NewFirewall(l, tcpTimeoutDuration, udpTimeoutDuration, defaultTimeoutDuration, c)
	return 0
}
