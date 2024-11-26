package fuzz_firewall

import (
	"net/netip"
	"time"

	"github.com/slackhq/nebula/cert"
)

type addRuleCall struct {
	incoming  bool
	proto     uint8
	startPort int32
	endPort   int32
	groups    []string
	host      string
	ip        netip.Prefix
	localIp   netip.Prefix
	caName    string
	caSha     string
}

type mockFirewall struct {
	lastCall       addRuleCall
	nextCallReturn error
}

func (mf *mockFirewall) AddRule(incoming bool, proto uint8, startPort int32, endPort int32, groups []string, host string, ip netip.Prefix, localIp netip.Prefix, caName string, caSha string) error {
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

type dummyCert struct {
	version        cert.Version
	curve          cert.Curve
	groups         []string
	isCa           bool
	issuer         string
	name           string
	networks       []netip.Prefix
	notAfter       time.Time
	notBefore      time.Time
	publicKey      []byte
	signature      []byte
	unsafeNetworks []netip.Prefix
}

func (d *dummyCert) Version() cert.Version {
	return d.version
}

func (d *dummyCert) Curve() cert.Curve {
	return d.curve
}

func (d *dummyCert) Groups() []string {
	return d.groups
}

func (d *dummyCert) IsCA() bool {
	return d.isCa
}

func (d *dummyCert) Issuer() string {
	return d.issuer
}

func (d *dummyCert) Name() string {
	return d.name
}

func (d *dummyCert) Networks() []netip.Prefix {
	return d.networks
}

func (d *dummyCert) NotAfter() time.Time {
	return d.notAfter
}

func (d *dummyCert) NotBefore() time.Time {
	return d.notBefore
}

func (d *dummyCert) PublicKey() []byte {
	return d.publicKey
}

func (d *dummyCert) Signature() []byte {
	return d.signature
}

func (d *dummyCert) UnsafeNetworks() []netip.Prefix {
	return d.unsafeNetworks
}

func (d *dummyCert) MarshalForHandshakes() ([]byte, error) {
	return nil, nil
}

func (d *dummyCert) Sign(curve cert.Curve, key []byte) error {
	return nil
}

func (d *dummyCert) CheckSignature(key []byte) bool {
	return true
}

func (d *dummyCert) Expired(t time.Time) bool {
	return false
}

func (d *dummyCert) CheckRootConstraints(signer cert.Certificate) error {
	return nil
}

func (d *dummyCert) VerifyPrivateKey(curve cert.Curve, key []byte) error {
	return nil
}

func (d *dummyCert) String() string {
	return ""
}

func (d *dummyCert) Marshal() ([]byte, error) {
	return nil, nil
}

func (d *dummyCert) MarshalPEM() ([]byte, error) {
	return nil, nil
}

func (d *dummyCert) Fingerprint() (string, error) {
	return "", nil
}

func (d *dummyCert) MarshalJSON() ([]byte, error) {
	return nil, nil
}

func (d *dummyCert) Copy() cert.Certificate {
	return d
}
