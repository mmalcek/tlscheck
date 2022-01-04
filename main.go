package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"

	"gopkg.in/yaml.v3"
)

type (
	tConnState struct {
		HandshakeOK bool                 `yaml:"handshakeOK"`
		TLSVersion  string               `yaml:"tlsVersion"`
		Cipher      string               `yaml:"cipher"`
		Chains      [][]tPeerCertificate `yaml:"chains"`
	}
	tPeerCertificate struct {
		Name                  string   `yaml:"name"`
		Issuer                string   `yaml:"issuer"`
		ValidFrom             string   `yaml:"validFrom"`
		ValidTo               string   `yaml:"validTo"`
		DNS                   []string `yaml:"dns,omitempty"`
		IP                    []net.IP `yaml:"ip,omitempty"`
		IssuingCertificateURL []string `yaml:"issuingCertificateURL,omitempty"`
		IsCA                  bool     `yaml:"isCA"`
	}
)

func main() {
	srvAddress := flag.String("a", "", "Server address")
	srvPort := flag.Int64("p", 0, "Server port")
	srvSkipVerify := flag.Bool("i", false, "Insecure - accepts any certificate")
	flag.Parse()
	if *srvAddress == "" || *srvPort == 0 {
		flag.Usage()
		return
	}

	conn, err := tls.Dial(
		"tcp",
		fmt.Sprintf("%s:%d", *srvAddress, *srvPort),
		&tls.Config{
			InsecureSkipVerify: *srvSkipVerify,
		},
	)
	if err != nil {
		log.Fatalf("Connection error: %s\r\n", err.Error())
	}
	defer conn.Close()

	var tlsState tConnState
	tlsState.HandshakeOK = conn.ConnectionState().HandshakeComplete
	versions := map[uint16]string{
		tls.VersionSSL30: "SSL",
		tls.VersionTLS10: "TLS 1.0",
		tls.VersionTLS11: "TLS 1.1",
		tls.VersionTLS12: "TLS 1.2",
		tls.VersionTLS13: "TLS 1.3",
	}
	tlsState.TLSVersion = versions[conn.ConnectionState().Version]
	tlsState.Cipher = tls.CipherSuiteName(conn.ConnectionState().CipherSuite)

	if conn.ConnectionState().VerifiedChains != nil {
		tlsState.Chains = make([][]tPeerCertificate, len(conn.ConnectionState().VerifiedChains))
		for i := range conn.ConnectionState().VerifiedChains {
			tlsState.Chains[i] = make([]tPeerCertificate, len(conn.ConnectionState().VerifiedChains[i]))
			for j := range conn.ConnectionState().VerifiedChains[i] {
				tlsState.Chains[i][j] = tPeerCertificate{
					Name:                  conn.ConnectionState().VerifiedChains[i][j].Subject.CommonName,
					Issuer:                conn.ConnectionState().VerifiedChains[i][j].Issuer.String(),
					ValidFrom:             conn.ConnectionState().VerifiedChains[i][j].NotBefore.Format("2006-01-02 15:04:05"),
					ValidTo:               conn.ConnectionState().VerifiedChains[i][j].NotAfter.Format("2006-01-02 15:04:05"),
					DNS:                   conn.ConnectionState().VerifiedChains[i][j].DNSNames,
					IP:                    conn.ConnectionState().VerifiedChains[i][j].IPAddresses,
					IssuingCertificateURL: conn.ConnectionState().VerifiedChains[i][j].IssuingCertificateURL,
					IsCA:                  conn.ConnectionState().VerifiedChains[i][j].IsCA,
				}
			}
		}
	}

	yamlState, err := yaml.Marshal(tlsState)
	if err != nil {
		log.Fatalf("yaml error: %s\r\n", err.Error())
	}
	fmt.Println(string(yamlState))
}
