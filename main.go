package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
)

func validity(cert *x509.Certificate) {
	fmt.Println("Validity")
	fmt.Println("  Not before:", cert.NotBefore)
	fmt.Println("  Not after:", cert.NotAfter)
}

func issuer(cert *x509.Certificate) {
	fmt.Println("Issuer:", cert.Issuer)
}

func serialNumber(cert *x509.Certificate) {
	serial := hex.EncodeToString(cert.SerialNumber.Bytes())
	fmt.Println("Serial Number:", serial)
}

func x509KeyIds(cert *x509.Certificate) {
	skid := hex.EncodeToString(cert.SubjectKeyId)
	akid := hex.EncodeToString(cert.AuthorityKeyId)
	fmt.Println("Subject Key Id:", skid)
	fmt.Println("Authority Key Id:", akid)
}

func subject(cert *x509.Certificate) {
	fmt.Println("Subject:", cert.Subject)
}

func san(cert *x509.Certificate) {
	fmt.Println("SANs")
	sans := strings.Join(cert.DNSNames, "\n  ")
	fmt.Println(" ", sans)
}

type Config struct {
	Hostname, Port string
}

func NewConfig() *Config {
	c := &Config{}
	flag.StringVar(&c.Hostname, "hostname", "", "target hostname")
	flag.StringVar(&c.Port, "port", "443", "target port")
	flag.Parse()
	if c.Hostname == "" {
		flag.Usage()
		os.Exit(0)
	}
	return c
}

func (c *Config) DialString() string {
	return c.Hostname+":"+c.Port
}

func main() {
	conf := NewConfig()

	conn, err := tls.Dial("tcp", conf.DialString(), nil)
	if err != nil {
		panic("Server doesn't support SSL certificate err: " + err.Error())
	}
	defer conn.Close()

	err = conn.VerifyHostname(conf.Hostname)
	if err != nil {
		panic("Hostname doesn't match with certificate: " + err.Error())
	}

	certificate := conn.ConnectionState().PeerCertificates[0]
	subject(certificate)
	issuer(certificate)
	serialNumber(certificate)
	x509KeyIds(certificate)
	validity(certificate)
	san(certificate)
}
