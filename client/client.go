package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
)

var (
	serverName       = flag.String("serverName", "tee.collaborator1.com", "SNI to connect to")
	serverCertRootCA = flag.String("serverCertRootCA", "ca1/root-ca.crt", "Root CA of the server cert")

	clientCert = flag.String("clientCert", "ca1/client.crt", "Client Certificate to use")
	clientKey  = flag.String("clientKey", "ca1/client.key", "Client cert key")
)

func main() {

	flag.Parse()

	caCert, err := ioutil.ReadFile(*serverCertRootCA)
	if err != nil {
		panic(err)
	}

	serverCertPool := x509.NewCertPool()
	serverCertPool.AppendCertsFromPEM(caCert)

	cert1, err := tls.LoadX509KeyPair(*clientCert, *clientKey)
	if err != nil {
		panic(err)
	}

	tlsConfig := &tls.Config{
		ServerName:   *serverName,
		RootCAs:      serverCertPool,
		Certificates: []tls.Certificate{cert1},
		MinVersion:   tls.VersionTLS13,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			for _, rawCert := range rawCerts {
				c, err := x509.ParseCertificate(rawCert)
				if err != nil {
					return err
				}
				// opts := x509.VerifyOptions{
				// 	Roots: serverCertPool,
				// 	KeyUsages: []x509.ExtKeyUsage{
				// 		x509.ExtKeyUsageServerAuth,
				// 	},
				// }
				// _, err = c.Verify(opts)
				// if err != nil {
				// 	return err
				// }
				fmt.Printf("Server Subject %s\n", c.Subject)
				fmt.Printf("Server Issuer %s\n", c.Issuer)
				fmt.Printf("Server Serial Number %s\n", c.SerialNumber)
			}
			return nil
		},
	}

	tr := &http.Transport{
		DialTLS: func(network, addr string) (net.Conn, error) {
			conn, err := tls.Dial(network, addr, tlsConfig)
			if err != nil {
				return conn, err
			}
			err = conn.Handshake()
			if err != nil {
				return conn, err
			}
			cs := conn.ConnectionState()

			ekm, err := cs.ExportKeyingMaterial("my_nonce", nil, 32)
			if err != nil {
				fmt.Errorf("ExportKeyingMaterial failed: %v\n", err)
				return nil, err
			}
			fmt.Printf("EKM my_nonce: %s\n", hex.EncodeToString(ekm))

			host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			ip := net.ParseIP(host)
			fmt.Printf("Connected to IP: %s\n", ip)
			return conn, nil
		},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get("https://localhost:8081")
	if err != nil {
		log.Println(err)
		return
	}

	htmlData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("%v\n", resp.Status)
	fmt.Printf(string(htmlData))

}
