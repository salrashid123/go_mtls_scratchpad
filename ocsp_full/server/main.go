package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	//"net/http/httputil"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/ocsp"
	"golang.org/x/net/http2"
)

var (
	serverCert         = flag.String("serverCert", "ca_scratchpad/certs/http.crt", "Server TLS Cert")
	serverKey          = flag.String("serverKey", "ca_scratchpad/certs/http.key", "Server TLS KEY")
	rootCA             = flag.String("rootCA", "ca_scratchpad/ca/root-ca.crt", "RootCA")
	ocspSigner         = flag.String("ocspSigner", "ca_scratchpad/certs/ocsp.crt", "OCSP SIgner")
	ocspResponseStatic = flag.String("ocspResponseStatic", "ca_scratchpad/http_server_ocsp_resp_valid.bin", "OCSP Response Bytes")

	crlFile = flag.String("crlFile", "ca_scratchpad/crl/root-ca-empty-valid.crl", "CRLFile to read")
)

const ()

func eventsMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		for _, cert := range r.TLS.PeerCertificates {
			fmt.Printf("Issuer Name: %s\n", cert.Issuer)
			fmt.Printf("Expiry: %s \n", cert.NotAfter.Format("2006-January-02"))
			fmt.Printf("Common Name: %s \n", cert.Subject.CommonName)
			fmt.Printf("IsCA: %t \n", cert.IsCA)

			hasher := sha256.New()
			hasher.Write(cert.Raw)
			clientCertificateHash := base64.StdEncoding.EncodeToString(hasher.Sum(nil))

			fmt.Printf("Certificate hash %s\n", clientCertificateHash)
			fmt.Println()

		}

		for _, cert := range r.TLS.VerifiedChains {
			for _, c := range cert {
				fmt.Printf("VerifiedChains Issuer Name: %s\n", c.Issuer)
				fmt.Printf("VerifiedChains Expiry: %s \n", c.NotAfter.Format("2006-January-02"))
				fmt.Printf("VerifiedChains Common Name: %s \n", c.Subject.CommonName)
				fmt.Printf("VerifiedChains IsCA: %t \n", c.IsCA)
				h := sha256.New()
				h.Write(c.Raw)
				clientCertificateHash := base64.StdEncoding.EncodeToString(h.Sum(nil))

				fmt.Printf("VerifiedChains Certificate hash %s\n", clientCertificateHash)
				fmt.Println()
			}
		}

		h.ServeHTTP(w, r)
	})
}

func gethandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "ok")
}

func main() {

	flag.Parse()

	router := mux.NewRouter()
	router.Methods(http.MethodGet).Path("/").HandlerFunc(gethandler)

	default_server_certs, err := tls.LoadX509KeyPair(*serverCert, *serverKey)
	if err != nil {
		panic(err)
	}

	rootPEM, err := os.ReadFile(*rootCA)
	if err != nil {
		panic(err)
	}

	rootblock, _ := pem.Decode(rootPEM)
	if rootblock == nil {
		panic("failed to decode PEM block")
	}

	ocspSignerPEM, err := os.ReadFile(*ocspSigner)
	if err != nil {
		panic(err)
	}

	ocspblock, _ := pem.Decode(ocspSignerPEM)
	if rootblock == nil {
		panic("failed to decode PEM block")
	}

	crlBytes, err := os.ReadFile(*crlFile)
	if err != nil {
		log.Fatal(err)
	}

	crlBlock, _ := pem.Decode(crlBytes)
	if rootblock == nil {
		panic("failed to decode PEM block")
	}

	crlList, err := x509.ParseRevocationList(crlBlock.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	// ocspServerResponse, err := os.ReadFile(*ocspResponseStatic)
	// if err != nil {
	// 	log.Println(err)
	// 	return
	// }

	serverCert, err := x509.ParseCertificate(default_server_certs.Certificate[0])
	if err != nil {
		panic(err)
	}

	root509Cert, err := x509.ParseCertificate(rootblock.Bytes)
	if err != nil {
		panic(err)
	}

	ocspSignerCert, err := x509.ParseCertificate(ocspblock.Bytes)
	if err != nil {
		panic(err)
	}

	cr, err := ocsp.CreateRequest(serverCert, ocspSignerCert, &ocsp.RequestOptions{})
	if err != nil {
		fmt.Printf("error creating request %v", err)
		return
	}

	or, err := http.NewRequest(http.MethodPost, "http://localhost:9999", bytes.NewBuffer(cr))
	if err != nil {
		panic(err)
	}
	client := &http.Client{}
	res, err := client.Do(or)
	if err != nil {
		panic(err)
	}

	defer res.Body.Close()
	ocspServerResponse, err := io.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}

	clientCaCert, err := os.ReadFile(*rootCA)
	if err != nil {
		panic(err)
	}
	clientCaCertPool := x509.NewCertPool()
	clientCaCertPool.AppendCertsFromPEM(clientCaCert)

	default_server_certs.OCSPStaple = ocspServerResponse

	tlsConfig := &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCaCertPool,
		Certificates: []tls.Certificate{default_server_certs},

		VerifyConnection: func(cs tls.ConnectionState) error {
			for _, c := range crlList.RevokedCertificateEntries {
				if c.SerialNumber.Uint64() == cs.PeerCertificates[0].SerialNumber.Uint64() {
					return fmt.Errorf("certificate revoked at %s", c.RevocationTime)
				}
			}
			ocspResp, err := ocsp.ParseResponse(cs.OCSPResponse, root509Cert)
			if err != nil {
				log.Printf("Could not read GCS Response Object Body. %v", err)
				return err
			}

			if ocspResp.NextUpdate.Before(time.Now()) {
				log.Printf(">>  Certificate with serialNumber [%x] Stale; Removing from Cache.", ocspResp.SerialNumber)
				return errors.New("certificate ocsp stale")
			}
			return nil
		},
	}

	sslKeyLogfile := os.Getenv("SSLKEYLOGFILE")
	if sslKeyLogfile != "" {
		var w *os.File
		w, err := os.OpenFile(sslKeyLogfile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			log.Fatalf("Could not create keylogger: %v", err)
		}
		tlsConfig.KeyLogWriter = w
	}

	server := &http.Server{
		Addr:      ":8081",
		Handler:   eventsMiddleware(router),
		TLSConfig: tlsConfig,
	}
	http2.ConfigureServer(server, &http2.Server{})
	fmt.Println("Starting Server..")
	err = server.ListenAndServeTLS("", "")
	fmt.Printf("Unable to start Server %v", err)

}
