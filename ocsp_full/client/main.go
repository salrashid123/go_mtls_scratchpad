package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/ocsp"
)

var (
	clientCert         = flag.String("clientCert", "ca_scratchpad/certs/client.crt", "Client TLS Cert")
	clientKey          = flag.String("clientKey", "ca_scratchpad/certs/client.key", "Client TLS KEY")
	rootCA             = flag.String("rootCA", "ca_scratchpad/ca/root-ca.crt", "RootCA")
	ocspSigner         = flag.String("ocspSigner", "ca_scratchpad/certs/ocsp.crt", "OCSP SIgner")
	ocspResponseStatic = flag.String("ocspResponseStatic", "ca_scratchpad/client_ocsp_resp_valid.bin", "OCSP Response Bytes")
)

func main() {

	flag.Parse()

	client_ocsp, err := os.ReadFile(*ocspResponseStatic)
	if err != nil {
		log.Println(err)
		return
	}

	caCert, err := os.ReadFile(*rootCA)
	if err != nil {
		log.Println(err)
		return
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	clientCerts, err := tls.LoadX509KeyPair(
		*clientCert,
		*clientKey,
	)
	if err != nil {
		log.Println(err)
		return
	}
	clientCerts.OCSPStaple = client_ocsp

	tlsConfig := &tls.Config{
		ServerName:   "http.domain.com",
		Certificates: []tls.Certificate{clientCerts},
		RootCAs:      caCertPool,
		VerifyConnection: func(cs tls.ConnectionState) error {

			ocspResp, err := ocsp.ParseResponse(cs.OCSPResponse, nil)
			if err != nil {
				log.Printf("Could not read GCS Response Object Body. %v", err)
				return err
			}

			if ocspResp.NextUpdate.Before(time.Now()) {
				log.Printf(">>  Certificate with serialNumber [%x] Stale; Removing from Cache.", ocspResp.SerialNumber)
				return errors.New("certificate ocsp stale")
			}

			if ocspResp.Status != ocsp.Good {
				return errors.New("ocsp status invalid")
			}

			return nil
		},
	}

	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get("https://localhost:8081")
	if err != nil {
		log.Println(err)
		return
	}

	htmlData, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("%v\n", resp.Status)
	fmt.Println(string(htmlData))

}
