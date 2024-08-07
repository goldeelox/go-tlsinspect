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

var DefaultPadding int = 20

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
	return c.Hostname + ":" + c.Port
}

func paddedPrint(key, value string, padding int) {
	if len(value) > 0 {
		fmt.Printf("%*s: %s\n", padding, key, value)
	}
}

func subject(cert *x509.Certificate) {
	paddedPrint("Subject", cert.Subject.String(), DefaultPadding)
}

func san(cert *x509.Certificate) {
	fmt.Printf("\nSANs\n")
	sans := strings.Join(cert.DNSNames, "\n  ")
	fmt.Println(" ", sans)
}

func certificate(cert *x509.Certificate) {
	fmt.Printf("\nCertificate\n")
	subject(cert)
	paddedPrint("Valid after", cert.NotBefore.String(), DefaultPadding)
	paddedPrint("Valid before", cert.NotAfter.String(), DefaultPadding)

	serial := hex.EncodeToString(cert.SerialNumber.Bytes())
	paddedPrint("Serial number", serial, DefaultPadding)

	skid := hex.EncodeToString(cert.SubjectKeyId)
	paddedPrint("Subject Key ID", skid, DefaultPadding)
	paddedPrint("Public key algorithm", cert.PublicKeyAlgorithm.String(), DefaultPadding)
}

func issuer(cert *x509.Certificate) {
	fmt.Printf("\nIssuer\n")
	paddedPrint("Subject", cert.Issuer.String(), DefaultPadding)

	akid := hex.EncodeToString(cert.AuthorityKeyId)
	paddedPrint("Authority Key ID", akid, DefaultPadding)
}

func connection(conn *tls.Conn) {
	fmt.Printf("\nConnection\n")
	cipherSuite := tls.CipherSuiteName(conn.ConnectionState().CipherSuite)
	tlsVersion := tls.VersionName(uint16(conn.ConnectionState().Version))
	paddedPrint("TLS version", tlsVersion, DefaultPadding)
	paddedPrint("Cipher suite", cipherSuite, DefaultPadding)
}

func main() {
	conf := NewConfig()

	conn, err := tls.Dial("tcp", conf.DialString(), nil)
	if err != nil {
		slog.Warn("server doesn't support SSL certificate",
			slog.String("msg", err.Error()))
	}
	defer conn.Close()

	err = conn.VerifyHostname(conf.Hostname)
	if err != nil {
		slog.Warn("hostname doesn't match certificate",
			slog.String("msg", err.Error()))
	}

	connection(conn)

	cert := conn.ConnectionState().PeerCertificates[0]
	issuer(cert)
	certificate(cert)
	san(cert)
}
