package nebula

import (
	"bytes"
	"errors"
	"math"
	"net"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/iputil"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
)

func TestNewFirewall(t *testing.T) {
	l := test.NewLogger()
	c := &cert.NebulaCertificate{}
	fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	conntrack := fw.Conntrack
	assert.NotNil(t, conntrack)
	assert.NotNil(t, conntrack.Conns)
	assert.NotNil(t, conntrack.TimerWheel)
	assert.NotNil(t, fw.InRules)
	assert.NotNil(t, fw.OutRules)
	assert.Equal(t, time.Second, fw.TCPTimeout)
	assert.Equal(t, time.Minute, fw.UDPTimeout)
	assert.Equal(t, time.Hour, fw.DefaultTimeout)

	assert.Equal(t, time.Hour, conntrack.TimerWheel.wheelDuration)
	assert.Equal(t, time.Hour, conntrack.TimerWheel.wheelDuration)
	assert.Equal(t, 3602, conntrack.TimerWheel.wheelLen)

	fw = NewFirewall(l, time.Second, time.Hour, time.Minute, c)
	assert.Equal(t, time.Hour, conntrack.TimerWheel.wheelDuration)
	assert.Equal(t, 3602, conntrack.TimerWheel.wheelLen)

	fw = NewFirewall(l, time.Hour, time.Second, time.Minute, c)
	assert.Equal(t, time.Hour, conntrack.TimerWheel.wheelDuration)
	assert.Equal(t, 3602, conntrack.TimerWheel.wheelLen)

	fw = NewFirewall(l, time.Hour, time.Minute, time.Second, c)
	assert.Equal(t, time.Hour, conntrack.TimerWheel.wheelDuration)
	assert.Equal(t, 3602, conntrack.TimerWheel.wheelLen)

	fw = NewFirewall(l, time.Minute, time.Hour, time.Second, c)
	assert.Equal(t, time.Hour, conntrack.TimerWheel.wheelDuration)
	assert.Equal(t, 3602, conntrack.TimerWheel.wheelLen)

	fw = NewFirewall(l, time.Minute, time.Second, time.Hour, c)
	assert.Equal(t, time.Hour, conntrack.TimerWheel.wheelDuration)
	assert.Equal(t, 3602, conntrack.TimerWheel.wheelLen)
}

func TestFirewall_AddRule(t *testing.T) {
	l := test.NewLogger()
	ob := &bytes.Buffer{}
	l.SetOutput(ob)

	c := &cert.NebulaCertificate{}
	fw := NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	assert.NotNil(t, fw.InRules)
	assert.NotNil(t, fw.OutRules)

	_, ti, _ := net.ParseCIDR("1.2.3.4/32")

	assert.Nil(t, fw.AddRule(true, firewall.ProtoTCP, 1, 1, []string{}, "", nil, nil, "", ""))
	// An empty rule is any
	assert.True(t, fw.InRules.TCP[1].Any.Any.Any)
	assert.Empty(t, fw.InRules.TCP[1].Any.Groups)
	assert.Empty(t, fw.InRules.TCP[1].Any.Hosts)

	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	assert.Nil(t, fw.AddRule(true, firewall.ProtoUDP, 1, 1, []string{"g1"}, "", nil, nil, "", ""))
	assert.Nil(t, fw.InRules.UDP[1].Any.Any)
	assert.Contains(t, fw.InRules.UDP[1].Any.Groups[0].Groups, "g1")
	assert.Empty(t, fw.InRules.UDP[1].Any.Hosts)

	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	assert.Nil(t, fw.AddRule(true, firewall.ProtoICMP, 1, 1, []string{}, "h1", nil, nil, "", ""))
	assert.Nil(t, fw.InRules.ICMP[1].Any.Any)
	assert.Empty(t, fw.InRules.ICMP[1].Any.Groups)
	assert.Contains(t, fw.InRules.ICMP[1].Any.Hosts, "h1")

	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	assert.Nil(t, fw.AddRule(false, firewall.ProtoAny, 1, 1, []string{}, "", ti, nil, "", ""))
	assert.Nil(t, fw.OutRules.AnyProto[1].Any.Any)
	ok, _ := fw.OutRules.AnyProto[1].Any.CIDR.GetCIDR(ti)
	assert.True(t, ok)

	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	assert.Nil(t, fw.AddRule(false, firewall.ProtoAny, 1, 1, []string{}, "", nil, ti, "", ""))
	assert.NotNil(t, fw.OutRules.AnyProto[1].Any.Any)
	ok, _ = fw.OutRules.AnyProto[1].Any.Any.LocalCIDR.GetCIDR(ti)
	assert.True(t, ok)

	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	assert.Nil(t, fw.AddRule(true, firewall.ProtoUDP, 1, 1, []string{"g1"}, "", nil, nil, "ca-name", ""))
	assert.Contains(t, fw.InRules.UDP[1].CANames, "ca-name")

	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	assert.Nil(t, fw.AddRule(true, firewall.ProtoUDP, 1, 1, []string{"g1"}, "", nil, nil, "", "ca-sha"))
	assert.Contains(t, fw.InRules.UDP[1].CAShas, "ca-sha")

	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	assert.Nil(t, fw.AddRule(false, firewall.ProtoAny, 0, 0, []string{}, "any", nil, nil, "", ""))
	assert.True(t, fw.OutRules.AnyProto[0].Any.Any.Any)

	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	_, anyIp, _ := net.ParseCIDR("0.0.0.0/0")
	assert.Nil(t, fw.AddRule(false, firewall.ProtoAny, 0, 0, []string{}, "", anyIp, nil, "", ""))
	assert.True(t, fw.OutRules.AnyProto[0].Any.Any.Any)

	// Test error conditions
	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, c)
	assert.Error(t, fw.AddRule(true, math.MaxUint8, 0, 0, []string{}, "", nil, nil, "", ""))
	assert.Error(t, fw.AddRule(true, firewall.ProtoAny, 10, 0, []string{}, "", nil, nil, "", ""))
}

func TestFirewall_Drop(t *testing.T) {
	l := test.NewLogger()
	ob := &bytes.Buffer{}
	l.SetOutput(ob)

	p := firewall.Packet{
		LocalIP:    iputil.Ip2VpnIp(net.IPv4(1, 2, 3, 4)),
		RemoteIP:   iputil.Ip2VpnIp(net.IPv4(1, 2, 3, 4)),
		LocalPort:  10,
		RemotePort: 90,
		Protocol:   firewall.ProtoUDP,
		Fragment:   false,
	}

	ipNet := net.IPNet{
		IP:   net.IPv4(1, 2, 3, 4),
		Mask: net.IPMask{255, 255, 255, 0},
	}

	c := cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:           "host1",
			Ips:            []*net.IPNet{&ipNet},
			Groups:         []string{"default-group"},
			InvertedGroups: map[string]struct{}{"default-group": {}},
			Issuer:         "signer-shasum",
		},
	}
	h := HostInfo{
		ConnectionState: &ConnectionState{
			peerCert: &c,
		},
		vpnIp: iputil.Ip2VpnIp(ipNet.IP),
	}
	h.CreateRemoteCIDR(&c)

	fw := NewFirewall(l, time.Second, time.Minute, time.Hour, &c)
	assert.Nil(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"any"}, "", nil, nil, "", ""))
	cp := cert.NewCAPool()

	// Drop outbound
	assert.Equal(t, fw.Drop(p, false, &h, cp, nil), ErrNoMatchingRule)
	// Allow inbound
	resetConntrack(fw)
	assert.NoError(t, fw.Drop(p, true, &h, cp, nil))
	// Allow outbound because conntrack
	assert.NoError(t, fw.Drop(p, false, &h, cp, nil))

	// test remote mismatch
	oldRemote := p.RemoteIP
	p.RemoteIP = iputil.Ip2VpnIp(net.IPv4(1, 2, 3, 10))
	assert.Equal(t, fw.Drop(p, false, &h, cp, nil), ErrInvalidRemoteIP)
	p.RemoteIP = oldRemote

	// ensure signer doesn't get in the way of group checks
	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, &c)
	assert.Nil(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"nope"}, "", nil, nil, "", "signer-shasum"))
	assert.Nil(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"default-group"}, "", nil, nil, "", "signer-shasum-bad"))
	assert.Equal(t, fw.Drop(p, true, &h, cp, nil), ErrNoMatchingRule)

	// test caSha doesn't drop on match
	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, &c)
	assert.Nil(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"nope"}, "", nil, nil, "", "signer-shasum-bad"))
	assert.Nil(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"default-group"}, "", nil, nil, "", "signer-shasum"))
	assert.NoError(t, fw.Drop(p, true, &h, cp, nil))

	// ensure ca name doesn't get in the way of group checks
	cp.CAs["signer-shasum"] = &cert.NebulaCertificate{Details: cert.NebulaCertificateDetails{Name: "ca-good"}}
	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, &c)
	assert.Nil(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"nope"}, "", nil, nil, "ca-good", ""))
	assert.Nil(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"default-group"}, "", nil, nil, "ca-good-bad", ""))
	assert.Equal(t, fw.Drop(p, true, &h, cp, nil), ErrNoMatchingRule)

	// test caName doesn't drop on match
	cp.CAs["signer-shasum"] = &cert.NebulaCertificate{Details: cert.NebulaCertificateDetails{Name: "ca-good"}}
	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, &c)
	assert.Nil(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"nope"}, "", nil, nil, "ca-good-bad", ""))
	assert.Nil(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"default-group"}, "", nil, nil, "ca-good", ""))
	assert.NoError(t, fw.Drop(p, true, &h, cp, nil))
}

func BenchmarkFirewallTable_match(b *testing.B) {
	f := &Firewall{}
	ft := FirewallTable{
		TCP: firewallPort{},
	}

	_, n, _ := net.ParseCIDR("172.1.1.1/32")
	goodLocalCIDRIP := iputil.Ip2VpnIp(n.IP)
	_ = ft.TCP.addRule(f, 10, 10, []string{"good-group"}, "good-host", n, nil, "", "")
	_ = ft.TCP.addRule(f, 100, 100, []string{"good-group"}, "good-host", nil, n, "", "")
	cp := cert.NewCAPool()

	b.Run("fail on proto", func(b *testing.B) {
		// This benchmark is showing us the cost of failing to match the protocol
		c := &cert.NebulaCertificate{}
		for n := 0; n < b.N; n++ {
			assert.False(b, ft.match(firewall.Packet{Protocol: firewall.ProtoUDP}, true, c, cp))
		}
	})

	b.Run("pass proto, fail on port", func(b *testing.B) {
		// This benchmark is showing us the cost of matching a specific protocol but failing to match the port
		c := &cert.NebulaCertificate{}
		for n := 0; n < b.N; n++ {
			assert.False(b, ft.match(firewall.Packet{Protocol: firewall.ProtoTCP, LocalPort: 1}, true, c, cp))
		}
	})

	b.Run("pass proto, port, fail on local CIDR", func(b *testing.B) {
		c := &cert.NebulaCertificate{}
		ip, _, _ := net.ParseCIDR("9.254.254.254/32")
		lip := iputil.Ip2VpnIp(ip)
		for n := 0; n < b.N; n++ {
			assert.False(b, ft.match(firewall.Packet{Protocol: firewall.ProtoTCP, LocalPort: 100, LocalIP: lip}, true, c, cp))
		}
	})

	b.Run("pass proto, port, any local CIDR, fail all group, name, and cidr", func(b *testing.B) {
		_, ip, _ := net.ParseCIDR("9.254.254.254/32")
		c := &cert.NebulaCertificate{
			Details: cert.NebulaCertificateDetails{
				InvertedGroups: map[string]struct{}{"nope": {}},
				Name:           "nope",
				Ips:            []*net.IPNet{ip},
			},
		}
		for n := 0; n < b.N; n++ {
			assert.False(b, ft.match(firewall.Packet{Protocol: firewall.ProtoTCP, LocalPort: 10}, true, c, cp))
		}
	})

	b.Run("pass proto, port, specific local CIDR, fail all group, name, and cidr", func(b *testing.B) {
		_, ip, _ := net.ParseCIDR("9.254.254.254/32")
		c := &cert.NebulaCertificate{
			Details: cert.NebulaCertificateDetails{
				InvertedGroups: map[string]struct{}{"nope": {}},
				Name:           "nope",
				Ips:            []*net.IPNet{ip},
			},
		}
		for n := 0; n < b.N; n++ {
			assert.False(b, ft.match(firewall.Packet{Protocol: firewall.ProtoTCP, LocalPort: 100, LocalIP: goodLocalCIDRIP}, true, c, cp))
		}
	})

	b.Run("pass on group on any local cidr", func(b *testing.B) {
		c := &cert.NebulaCertificate{
			Details: cert.NebulaCertificateDetails{
				InvertedGroups: map[string]struct{}{"good-group": {}},
				Name:           "nope",
			},
		}
		for n := 0; n < b.N; n++ {
			assert.True(b, ft.match(firewall.Packet{Protocol: firewall.ProtoTCP, LocalPort: 10}, true, c, cp))
		}
	})

	b.Run("pass on group on specific local cidr", func(b *testing.B) {
		c := &cert.NebulaCertificate{
			Details: cert.NebulaCertificateDetails{
				InvertedGroups: map[string]struct{}{"good-group": {}},
				Name:           "nope",
			},
		}
		for n := 0; n < b.N; n++ {
			assert.True(b, ft.match(firewall.Packet{Protocol: firewall.ProtoTCP, LocalPort: 100, LocalIP: goodLocalCIDRIP}, true, c, cp))
		}
	})

	b.Run("pass on name", func(b *testing.B) {
		c := &cert.NebulaCertificate{
			Details: cert.NebulaCertificateDetails{
				InvertedGroups: map[string]struct{}{"nope": {}},
				Name:           "good-host",
			},
		}
		for n := 0; n < b.N; n++ {
			ft.match(firewall.Packet{Protocol: firewall.ProtoTCP, LocalPort: 10}, true, c, cp)
		}
	})
	//
	//b.Run("pass on ip", func(b *testing.B) {
	//	ip := iputil.Ip2VpnIp(net.IPv4(172, 1, 1, 1))
	//	c := &cert.NebulaCertificate{
	//		Details: cert.NebulaCertificateDetails{
	//			InvertedGroups: map[string]struct{}{"nope": {}},
	//			Name:           "good-host",
	//		},
	//	}
	//	for n := 0; n < b.N; n++ {
	//		ft.match(firewall.Packet{Protocol: firewall.ProtoTCP, LocalPort: 10, RemoteIP: ip}, true, c, cp)
	//	}
	//})
	//
	//b.Run("pass on local ip", func(b *testing.B) {
	//	ip := iputil.Ip2VpnIp(net.IPv4(172, 1, 1, 1))
	//	c := &cert.NebulaCertificate{
	//		Details: cert.NebulaCertificateDetails{
	//			InvertedGroups: map[string]struct{}{"nope": {}},
	//			Name:           "good-host",
	//		},
	//	}
	//	for n := 0; n < b.N; n++ {
	//		ft.match(firewall.Packet{Protocol: firewall.ProtoTCP, LocalPort: 10, LocalIP: ip}, true, c, cp)
	//	}
	//})
	//
	//_ = ft.TCP.addRule(0, 0, []string{"good-group"}, "good-host", n, n, "", "")
	//
	//b.Run("pass on ip with any port", func(b *testing.B) {
	//	ip := iputil.Ip2VpnIp(net.IPv4(172, 1, 1, 1))
	//	c := &cert.NebulaCertificate{
	//		Details: cert.NebulaCertificateDetails{
	//			InvertedGroups: map[string]struct{}{"nope": {}},
	//			Name:           "good-host",
	//		},
	//	}
	//	for n := 0; n < b.N; n++ {
	//		ft.match(firewall.Packet{Protocol: firewall.ProtoTCP, LocalPort: 100, RemoteIP: ip}, true, c, cp)
	//	}
	//})
	//
	//b.Run("pass on local ip with any port", func(b *testing.B) {
	//	ip := iputil.Ip2VpnIp(net.IPv4(172, 1, 1, 1))
	//	c := &cert.NebulaCertificate{
	//		Details: cert.NebulaCertificateDetails{
	//			InvertedGroups: map[string]struct{}{"nope": {}},
	//			Name:           "good-host",
	//		},
	//	}
	//	for n := 0; n < b.N; n++ {
	//		ft.match(firewall.Packet{Protocol: firewall.ProtoTCP, LocalPort: 100, LocalIP: ip}, true, c, cp)
	//	}
	//})
}

func TestFirewall_Drop2(t *testing.T) {
	l := test.NewLogger()
	ob := &bytes.Buffer{}
	l.SetOutput(ob)

	p := firewall.Packet{
		LocalIP:    iputil.Ip2VpnIp(net.IPv4(1, 2, 3, 4)),
		RemoteIP:   iputil.Ip2VpnIp(net.IPv4(1, 2, 3, 4)),
		LocalPort:  10,
		RemotePort: 90,
		Protocol:   firewall.ProtoUDP,
		Fragment:   false,
	}

	ipNet := net.IPNet{
		IP:   net.IPv4(1, 2, 3, 4),
		Mask: net.IPMask{255, 255, 255, 0},
	}

	c := cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:           "host1",
			Ips:            []*net.IPNet{&ipNet},
			InvertedGroups: map[string]struct{}{"default-group": {}, "test-group": {}},
		},
	}
	h := HostInfo{
		ConnectionState: &ConnectionState{
			peerCert: &c,
		},
		vpnIp: iputil.Ip2VpnIp(ipNet.IP),
	}
	h.CreateRemoteCIDR(&c)

	c1 := cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:           "host1",
			Ips:            []*net.IPNet{&ipNet},
			InvertedGroups: map[string]struct{}{"default-group": {}, "test-group-not": {}},
		},
	}
	h1 := HostInfo{
		ConnectionState: &ConnectionState{
			peerCert: &c1,
		},
	}
	h1.CreateRemoteCIDR(&c1)

	fw := NewFirewall(l, time.Second, time.Minute, time.Hour, &c)
	assert.Nil(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"default-group", "test-group"}, "", nil, nil, "", ""))
	cp := cert.NewCAPool()

	// h1/c1 lacks the proper groups
	assert.Error(t, fw.Drop(p, true, &h1, cp, nil), ErrNoMatchingRule)
	// c has the proper groups
	resetConntrack(fw)
	assert.NoError(t, fw.Drop(p, true, &h, cp, nil))
}

func TestFirewall_Drop3(t *testing.T) {
	l := test.NewLogger()
	ob := &bytes.Buffer{}
	l.SetOutput(ob)

	p := firewall.Packet{
		LocalIP:    iputil.Ip2VpnIp(net.IPv4(1, 2, 3, 4)),
		RemoteIP:   iputil.Ip2VpnIp(net.IPv4(1, 2, 3, 4)),
		LocalPort:  1,
		RemotePort: 1,
		Protocol:   firewall.ProtoUDP,
		Fragment:   false,
	}

	ipNet := net.IPNet{
		IP:   net.IPv4(1, 2, 3, 4),
		Mask: net.IPMask{255, 255, 255, 0},
	}

	c := cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name: "host-owner",
			Ips:  []*net.IPNet{&ipNet},
		},
	}

	c1 := cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:   "host1",
			Ips:    []*net.IPNet{&ipNet},
			Issuer: "signer-sha-bad",
		},
	}
	h1 := HostInfo{
		ConnectionState: &ConnectionState{
			peerCert: &c1,
		},
		vpnIp: iputil.Ip2VpnIp(ipNet.IP),
	}
	h1.CreateRemoteCIDR(&c1)

	c2 := cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:   "host2",
			Ips:    []*net.IPNet{&ipNet},
			Issuer: "signer-sha",
		},
	}
	h2 := HostInfo{
		ConnectionState: &ConnectionState{
			peerCert: &c2,
		},
		vpnIp: iputil.Ip2VpnIp(ipNet.IP),
	}
	h2.CreateRemoteCIDR(&c2)

	c3 := cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:   "host3",
			Ips:    []*net.IPNet{&ipNet},
			Issuer: "signer-sha-bad",
		},
	}
	h3 := HostInfo{
		ConnectionState: &ConnectionState{
			peerCert: &c3,
		},
		vpnIp: iputil.Ip2VpnIp(ipNet.IP),
	}
	h3.CreateRemoteCIDR(&c3)

	fw := NewFirewall(l, time.Second, time.Minute, time.Hour, &c)
	assert.Nil(t, fw.AddRule(true, firewall.ProtoAny, 1, 1, []string{}, "host1", nil, nil, "", ""))
	assert.Nil(t, fw.AddRule(true, firewall.ProtoAny, 1, 1, []string{}, "", nil, nil, "", "signer-sha"))
	cp := cert.NewCAPool()

	// c1 should pass because host match
	assert.NoError(t, fw.Drop(p, true, &h1, cp, nil))
	// c2 should pass because ca sha match
	resetConntrack(fw)
	assert.NoError(t, fw.Drop(p, true, &h2, cp, nil))
	// c3 should fail because no match
	resetConntrack(fw)
	assert.Equal(t, fw.Drop(p, true, &h3, cp, nil), ErrNoMatchingRule)
}

func TestFirewall_DropConntrackReload(t *testing.T) {
	l := test.NewLogger()
	ob := &bytes.Buffer{}
	l.SetOutput(ob)

	p := firewall.Packet{
		LocalIP:    iputil.Ip2VpnIp(net.IPv4(1, 2, 3, 4)),
		RemoteIP:   iputil.Ip2VpnIp(net.IPv4(1, 2, 3, 4)),
		LocalPort:  10,
		RemotePort: 90,
		Protocol:   firewall.ProtoUDP,
		Fragment:   false,
	}

	ipNet := net.IPNet{
		IP:   net.IPv4(1, 2, 3, 4),
		Mask: net.IPMask{255, 255, 255, 0},
	}

	c := cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:           "host1",
			Ips:            []*net.IPNet{&ipNet},
			Groups:         []string{"default-group"},
			InvertedGroups: map[string]struct{}{"default-group": {}},
			Issuer:         "signer-shasum",
		},
	}
	h := HostInfo{
		ConnectionState: &ConnectionState{
			peerCert: &c,
		},
		vpnIp: iputil.Ip2VpnIp(ipNet.IP),
	}
	h.CreateRemoteCIDR(&c)

	fw := NewFirewall(l, time.Second, time.Minute, time.Hour, &c)
	assert.Nil(t, fw.AddRule(true, firewall.ProtoAny, 0, 0, []string{"any"}, "", nil, nil, "", ""))
	cp := cert.NewCAPool()

	// Drop outbound
	assert.Equal(t, fw.Drop(p, false, &h, cp, nil), ErrNoMatchingRule)
	// Allow inbound
	resetConntrack(fw)
	assert.NoError(t, fw.Drop(p, true, &h, cp, nil))
	// Allow outbound because conntrack
	assert.NoError(t, fw.Drop(p, false, &h, cp, nil))

	oldFw := fw
	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, &c)
	assert.Nil(t, fw.AddRule(true, firewall.ProtoAny, 10, 10, []string{"any"}, "", nil, nil, "", ""))
	fw.Conntrack = oldFw.Conntrack
	fw.rulesVersion = oldFw.rulesVersion + 1

	// Allow outbound because conntrack and new rules allow port 10
	assert.NoError(t, fw.Drop(p, false, &h, cp, nil))

	oldFw = fw
	fw = NewFirewall(l, time.Second, time.Minute, time.Hour, &c)
	assert.Nil(t, fw.AddRule(true, firewall.ProtoAny, 11, 11, []string{"any"}, "", nil, nil, "", ""))
	fw.Conntrack = oldFw.Conntrack
	fw.rulesVersion = oldFw.rulesVersion + 1

	// Drop outbound because conntrack doesn't match new ruleset
	assert.Equal(t, fw.Drop(p, false, &h, cp, nil), ErrNoMatchingRule)
}

func BenchmarkLookup(b *testing.B) {
	ml := func(m map[string]struct{}, a [][]string) {
		for n := 0; n < b.N; n++ {
			for _, sg := range a {
				found := false

				for _, g := range sg {
					if _, ok := m[g]; !ok {
						found = false
						break
					}

					found = true
				}

				if found {
					return
				}
			}
		}
	}

	b.Run("array to map best", func(b *testing.B) {
		m := map[string]struct{}{
			"1ne": {},
			"2wo": {},
			"3hr": {},
			"4ou": {},
			"5iv": {},
			"6ix": {},
		}

		a := [][]string{
			{"1ne", "2wo", "3hr", "4ou", "5iv", "6ix"},
			{"one", "2wo", "3hr", "4ou", "5iv", "6ix"},
			{"one", "two", "3hr", "4ou", "5iv", "6ix"},
			{"one", "two", "thr", "4ou", "5iv", "6ix"},
			{"one", "two", "thr", "fou", "5iv", "6ix"},
			{"one", "two", "thr", "fou", "fiv", "6ix"},
			{"one", "two", "thr", "fou", "fiv", "six"},
		}

		for n := 0; n < b.N; n++ {
			ml(m, a)
		}
	})

	b.Run("array to map worst", func(b *testing.B) {
		m := map[string]struct{}{
			"one": {},
			"two": {},
			"thr": {},
			"fou": {},
			"fiv": {},
			"six": {},
		}

		a := [][]string{
			{"1ne", "2wo", "3hr", "4ou", "5iv", "6ix"},
			{"one", "2wo", "3hr", "4ou", "5iv", "6ix"},
			{"one", "two", "3hr", "4ou", "5iv", "6ix"},
			{"one", "two", "thr", "4ou", "5iv", "6ix"},
			{"one", "two", "thr", "fou", "5iv", "6ix"},
			{"one", "two", "thr", "fou", "fiv", "6ix"},
			{"one", "two", "thr", "fou", "fiv", "six"},
		}

		for n := 0; n < b.N; n++ {
			ml(m, a)
		}
	})

	//TODO: only way array lookup in array will help is if both are sorted, then maybe it's faster
}

func Test_parsePort(t *testing.T) {
	_, _, err := parsePort("")
	assert.EqualError(t, err, "was not a number; ``")

	_, _, err = parsePort("  ")
	assert.EqualError(t, err, "was not a number; `  `")

	_, _, err = parsePort("-")
	assert.EqualError(t, err, "appears to be a range but could not be parsed; `-`")

	_, _, err = parsePort(" - ")
	assert.EqualError(t, err, "appears to be a range but could not be parsed; ` - `")

	_, _, err = parsePort("a-b")
	assert.EqualError(t, err, "beginning range was not a number; `a`")

	_, _, err = parsePort("1-b")
	assert.EqualError(t, err, "ending range was not a number; `b`")

	s, e, err := parsePort(" 1 - 2    ")
	assert.Equal(t, int32(1), s)
	assert.Equal(t, int32(2), e)
	assert.Nil(t, err)

	s, e, err = parsePort("0-1")
	assert.Equal(t, int32(0), s)
	assert.Equal(t, int32(0), e)
	assert.Nil(t, err)

	s, e, err = parsePort("9919")
	assert.Equal(t, int32(9919), s)
	assert.Equal(t, int32(9919), e)
	assert.Nil(t, err)

	s, e, err = parsePort("any")
	assert.Equal(t, int32(0), s)
	assert.Equal(t, int32(0), e)
	assert.Nil(t, err)
}

func TestNewFirewallFromConfig(t *testing.T) {
	l := test.NewLogger()
	// Test a bad rule definition
	c := &cert.NebulaCertificate{}
	conf := config.NewC(l)
	conf.Settings["firewall"] = map[interface{}]interface{}{"outbound": "asdf"}
	_, err := NewFirewallFromConfig(l, c, conf)
	assert.EqualError(t, err, "firewall.outbound failed to parse, should be an array of rules")

	// Test both port and code
	conf = config.NewC(l)
	conf.Settings["firewall"] = map[interface{}]interface{}{"outbound": []interface{}{map[interface{}]interface{}{"port": "1", "code": "2"}}}
	_, err = NewFirewallFromConfig(l, c, conf)
	assert.EqualError(t, err, "firewall.outbound rule #0; only one of port or code should be provided")

	// Test missing host, group, cidr, ca_name and ca_sha
	conf = config.NewC(l)
	conf.Settings["firewall"] = map[interface{}]interface{}{"outbound": []interface{}{map[interface{}]interface{}{}}}
	_, err = NewFirewallFromConfig(l, c, conf)
	assert.EqualError(t, err, "firewall.outbound rule #0; at least one of host, group, cidr, local_cidr, ca_name, or ca_sha must be provided")

	// Test code/port error
	conf = config.NewC(l)
	conf.Settings["firewall"] = map[interface{}]interface{}{"outbound": []interface{}{map[interface{}]interface{}{"code": "a", "host": "testh"}}}
	_, err = NewFirewallFromConfig(l, c, conf)
	assert.EqualError(t, err, "firewall.outbound rule #0; code was not a number; `a`")

	conf.Settings["firewall"] = map[interface{}]interface{}{"outbound": []interface{}{map[interface{}]interface{}{"port": "a", "host": "testh"}}}
	_, err = NewFirewallFromConfig(l, c, conf)
	assert.EqualError(t, err, "firewall.outbound rule #0; port was not a number; `a`")

	// Test proto error
	conf = config.NewC(l)
	conf.Settings["firewall"] = map[interface{}]interface{}{"outbound": []interface{}{map[interface{}]interface{}{"code": "1", "host": "testh"}}}
	_, err = NewFirewallFromConfig(l, c, conf)
	assert.EqualError(t, err, "firewall.outbound rule #0; proto was not understood; ``")

	// Test cidr parse error
	conf = config.NewC(l)
	conf.Settings["firewall"] = map[interface{}]interface{}{"outbound": []interface{}{map[interface{}]interface{}{"code": "1", "cidr": "testh", "proto": "any"}}}
	_, err = NewFirewallFromConfig(l, c, conf)
	assert.EqualError(t, err, "firewall.outbound rule #0; cidr did not parse; invalid CIDR address: testh")

	// Test local_cidr parse error
	conf = config.NewC(l)
	conf.Settings["firewall"] = map[interface{}]interface{}{"outbound": []interface{}{map[interface{}]interface{}{"code": "1", "local_cidr": "testh", "proto": "any"}}}
	_, err = NewFirewallFromConfig(l, c, conf)
	assert.EqualError(t, err, "firewall.outbound rule #0; local_cidr did not parse; invalid CIDR address: testh")

	// Test both group and groups
	conf = config.NewC(l)
	conf.Settings["firewall"] = map[interface{}]interface{}{"inbound": []interface{}{map[interface{}]interface{}{"port": "1", "proto": "any", "group": "a", "groups": []string{"b", "c"}}}}
	_, err = NewFirewallFromConfig(l, c, conf)
	assert.EqualError(t, err, "firewall.inbound rule #0; only one of group or groups should be defined, both provided")
}

func TestAddFirewallRulesFromConfig(t *testing.T) {
	l := test.NewLogger()
	// Test adding tcp rule
	conf := config.NewC(l)
	mf := &mockFirewall{}
	conf.Settings["firewall"] = map[interface{}]interface{}{"outbound": []interface{}{map[interface{}]interface{}{"port": "1", "proto": "tcp", "host": "a"}}}
	assert.Nil(t, AddFirewallRulesFromConfig(l, false, conf, mf))
	assert.Equal(t, addRuleCall{incoming: false, proto: firewall.ProtoTCP, startPort: 1, endPort: 1, groups: nil, host: "a", ip: nil, localIp: nil}, mf.lastCall)

	// Test adding udp rule
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[interface{}]interface{}{"outbound": []interface{}{map[interface{}]interface{}{"port": "1", "proto": "udp", "host": "a"}}}
	assert.Nil(t, AddFirewallRulesFromConfig(l, false, conf, mf))
	assert.Equal(t, addRuleCall{incoming: false, proto: firewall.ProtoUDP, startPort: 1, endPort: 1, groups: nil, host: "a", ip: nil, localIp: nil}, mf.lastCall)

	// Test adding icmp rule
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[interface{}]interface{}{"outbound": []interface{}{map[interface{}]interface{}{"port": "1", "proto": "icmp", "host": "a"}}}
	assert.Nil(t, AddFirewallRulesFromConfig(l, false, conf, mf))
	assert.Equal(t, addRuleCall{incoming: false, proto: firewall.ProtoICMP, startPort: 1, endPort: 1, groups: nil, host: "a", ip: nil, localIp: nil}, mf.lastCall)

	// Test adding any rule
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[interface{}]interface{}{"inbound": []interface{}{map[interface{}]interface{}{"port": "1", "proto": "any", "host": "a"}}}
	assert.Nil(t, AddFirewallRulesFromConfig(l, true, conf, mf))
	assert.Equal(t, addRuleCall{incoming: true, proto: firewall.ProtoAny, startPort: 1, endPort: 1, groups: nil, host: "a", ip: nil, localIp: nil}, mf.lastCall)

	// Test adding rule with cidr
	cidr := &net.IPNet{IP: net.ParseIP("10.0.0.0").To4(), Mask: net.IPv4Mask(255, 0, 0, 0)}
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[interface{}]interface{}{"inbound": []interface{}{map[interface{}]interface{}{"port": "1", "proto": "any", "cidr": cidr.String()}}}
	assert.Nil(t, AddFirewallRulesFromConfig(l, true, conf, mf))
	assert.Equal(t, addRuleCall{incoming: true, proto: firewall.ProtoAny, startPort: 1, endPort: 1, groups: nil, ip: cidr, localIp: nil}, mf.lastCall)

	// Test adding rule with local_cidr
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[interface{}]interface{}{"inbound": []interface{}{map[interface{}]interface{}{"port": "1", "proto": "any", "local_cidr": cidr.String()}}}
	assert.Nil(t, AddFirewallRulesFromConfig(l, true, conf, mf))
	assert.Equal(t, addRuleCall{incoming: true, proto: firewall.ProtoAny, startPort: 1, endPort: 1, groups: nil, ip: nil, localIp: cidr}, mf.lastCall)

	// Test adding rule with ca_sha
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[interface{}]interface{}{"inbound": []interface{}{map[interface{}]interface{}{"port": "1", "proto": "any", "ca_sha": "12312313123"}}}
	assert.Nil(t, AddFirewallRulesFromConfig(l, true, conf, mf))
	assert.Equal(t, addRuleCall{incoming: true, proto: firewall.ProtoAny, startPort: 1, endPort: 1, groups: nil, ip: nil, localIp: nil, caSha: "12312313123"}, mf.lastCall)

	// Test adding rule with ca_name
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[interface{}]interface{}{"inbound": []interface{}{map[interface{}]interface{}{"port": "1", "proto": "any", "ca_name": "root01"}}}
	assert.Nil(t, AddFirewallRulesFromConfig(l, true, conf, mf))
	assert.Equal(t, addRuleCall{incoming: true, proto: firewall.ProtoAny, startPort: 1, endPort: 1, groups: nil, ip: nil, localIp: nil, caName: "root01"}, mf.lastCall)

	// Test single group
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[interface{}]interface{}{"inbound": []interface{}{map[interface{}]interface{}{"port": "1", "proto": "any", "group": "a"}}}
	assert.Nil(t, AddFirewallRulesFromConfig(l, true, conf, mf))
	assert.Equal(t, addRuleCall{incoming: true, proto: firewall.ProtoAny, startPort: 1, endPort: 1, groups: []string{"a"}, ip: nil, localIp: nil}, mf.lastCall)

	// Test single groups
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[interface{}]interface{}{"inbound": []interface{}{map[interface{}]interface{}{"port": "1", "proto": "any", "groups": "a"}}}
	assert.Nil(t, AddFirewallRulesFromConfig(l, true, conf, mf))
	assert.Equal(t, addRuleCall{incoming: true, proto: firewall.ProtoAny, startPort: 1, endPort: 1, groups: []string{"a"}, ip: nil, localIp: nil}, mf.lastCall)

	// Test multiple AND groups
	conf = config.NewC(l)
	mf = &mockFirewall{}
	conf.Settings["firewall"] = map[interface{}]interface{}{"inbound": []interface{}{map[interface{}]interface{}{"port": "1", "proto": "any", "groups": []string{"a", "b"}}}}
	assert.Nil(t, AddFirewallRulesFromConfig(l, true, conf, mf))
	assert.Equal(t, addRuleCall{incoming: true, proto: firewall.ProtoAny, startPort: 1, endPort: 1, groups: []string{"a", "b"}, ip: nil, localIp: nil}, mf.lastCall)

	// Test Add error
	conf = config.NewC(l)
	mf = &mockFirewall{}
	mf.nextCallReturn = errors.New("test error")
	conf.Settings["firewall"] = map[interface{}]interface{}{"inbound": []interface{}{map[interface{}]interface{}{"port": "1", "proto": "any", "host": "a"}}}
	assert.EqualError(t, AddFirewallRulesFromConfig(l, true, conf, mf), "firewall.inbound rule #0; `test error`")
}

func TestFirewall_convertRule(t *testing.T) {
	l := test.NewLogger()
	ob := &bytes.Buffer{}
	l.SetOutput(ob)

	// Ensure group array of 1 is converted and a warning is printed
	c := map[interface{}]interface{}{
		"group": []interface{}{"group1"},
	}

	r, err := convertRule(l, c, "test", 1)
	assert.Contains(t, ob.String(), "test rule #1; group was an array with a single value, converting to simple value")
	assert.Nil(t, err)
	assert.Equal(t, "group1", r.Group)

	// Ensure group array of > 1 is errord
	ob.Reset()
	c = map[interface{}]interface{}{
		"group": []interface{}{"group1", "group2"},
	}

	r, err = convertRule(l, c, "test", 1)
	assert.Equal(t, "", ob.String())
	assert.Error(t, err, "group should contain a single value, an array with more than one entry was provided")

	// Make sure a well formed group is alright
	ob.Reset()
	c = map[interface{}]interface{}{
		"group": "group1",
	}

	r, err = convertRule(l, c, "test", 1)
	assert.Nil(t, err)
	assert.Equal(t, "group1", r.Group)
}

type addRuleCall struct {
	incoming  bool
	proto     uint8
	startPort int32
	endPort   int32
	groups    []string
	host      string
	ip        *net.IPNet
	localIp   *net.IPNet
	caName    string
	caSha     string
}

type mockFirewall struct {
	lastCall       addRuleCall
	nextCallReturn error
}

func (mf *mockFirewall) AddRule(incoming bool, proto uint8, startPort int32, endPort int32, groups []string, host string, ip *net.IPNet, localIp *net.IPNet, caName string, caSha string) error {
	mf.lastCall = addRuleCall{
		incoming:  incoming,
		proto:     proto,
		startPort: startPort,
		endPort:   endPort,
		groups:    groups,
		host:      host,
		ip:        ip,
		localIp:   localIp,
		caName:    caName,
		caSha:     caSha,
	}

	err := mf.nextCallReturn
	mf.nextCallReturn = nil
	return err
}

func resetConntrack(fw *Firewall) {
	fw.Conntrack.Lock()
	fw.Conntrack.Conns = map[firewall.Packet]*conn{}
	fw.Conntrack.Unlock()
}
