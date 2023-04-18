package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"

	//"net/http/httputil"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/ocsp"
	"golang.org/x/net/http2"
)

var (
	check_ocsp = flag.Bool("check_ocsp", false, "check ocsp server")
)

const (
	ca_1_ocsp_endpoint = "http://localhost:9999"
)

// contextKey is used to pass http middleware certificate details
type contextKey string

const contextEventKey contextKey = "event"

type event struct {
	PeerCertificates []*x509.Certificate
}

// middleware to extract the mtls client certificate
func eventsMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		event := &event{
			PeerCertificates: r.TLS.PeerCertificates,
		}
		ctx := context.WithValue(r.Context(), contextEventKey, *event)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

func gethandler(w http.ResponseWriter, r *http.Request) {
	val := r.Context().Value(contextKey("event")).(event)
	for _, c := range val.PeerCertificates {
		h := sha256.New()
		h.Write(c.Raw)
		fmt.Printf("Client Certificate hash %s\n", base64.RawURLEncoding.EncodeToString(h.Sum(nil)))
	}
	fmt.Fprint(w, "ok")
}

func main() {

	flag.Parse()
	router := mux.NewRouter()
	router.Methods(http.MethodGet).Path("/").HandlerFunc(gethandler)

	// load default server certs
	default_server_certs, err := tls.LoadX509KeyPair("ca_operator/tee.crt", "ca_operator/tee.key")
	if err != nil {
		panic(err)
	}

	// load rootCA for CA_1
	client1_root, err := ioutil.ReadFile("ca1/root-ca.crt")
	if err != nil {
		panic(err)
	}

	client_cert_pool := x509.NewCertPool()
	client_cert_pool.AppendCertsFromPEM(client1_root)

	// parse ca1's root for use with the ocsp request
	blockcrt, _ := pem.Decode([]byte(client1_root))
	client1_root_cert, err := x509.ParseCertificate(blockcrt.Bytes)
	if err != nil {
		panic(err)
	}

	// load rootCA for CA_2
	client2_root, err := ioutil.ReadFile("ca2/root-ca.crt")
	if err != nil {
		panic(err)
	}
	client_cert_pool.AppendCertsFromPEM(client2_root)

	// load the server certs issued by both ca1 and ca2
	server1_cert, err := tls.LoadX509KeyPair("ca1/tee.crt", "ca1/tee.key")
	if err != nil {
		panic(err)
	}

	server2_cert, err := tls.LoadX509KeyPair("ca2/tee.crt", "ca2/tee.key")
	if err != nil {
		panic(err)
	}

	// for debug ssl keylog
	sslKeyLogfile := os.Getenv("SSLKEYLOGFILE")
	var w *os.File
	if sslKeyLogfile != "" {
		w, err = os.OpenFile(sslKeyLogfile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			panic(err)
		}
	} else {
		w = os.Stdout
	}

	// *****************************************

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{default_server_certs, server1_cert, server2_cert},
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    client_cert_pool,

		KeyLogWriter: w,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			for _, rawCert := range rawCerts {
				c, err := x509.ParseCertificate(rawCert)
				if err != nil {
					return err
				}
				fmt.Printf("Subject %s\n", c.Subject)
				// opts := x509.VerifyOptions{
				// 	Roots: client_cert_pool,
				// 	KeyUsages: []x509.ExtKeyUsage{
				// 		x509.ExtKeyUsageClientAuth,
				// 	},
				// }
				// reverifiedChains, err = c.Verify(opts)
				// if err != nil {
				// 	return err
				// }

				if *check_ocsp {
					// now check ocsp if its ca1 (and w'ere running the ocsp server)
					for _, cch := range verifiedChains {
						for _, c := range cch {
							if c.Equal(client1_root_cert) {
								fmt.Println("Checking OCSP Server")
								ocsp_opts := &ocsp.RequestOptions{Hash: crypto.SHA1}
								buffer, err := ocsp.CreateRequest(c, client1_root_cert, ocsp_opts)
								if err != nil {
									return err
								}
								httpRequest, err := http.NewRequest(http.MethodPost, ca_1_ocsp_endpoint, bytes.NewBuffer(buffer))
								if err != nil {
									return err
								}
								ocspUrl, err := url.Parse(ca_1_ocsp_endpoint)
								if err != nil {
									return err
								}
								httpRequest.Header.Add("Content-Type", "application/ocsp-request")
								httpRequest.Header.Add("Accept", "application/ocsp-response")
								httpRequest.Header.Add("host", ocspUrl.Host)
								httpClient := &http.Client{}
								httpResponse, err := httpClient.Do(httpRequest)
								if err != nil {
									return err
								}
								defer httpResponse.Body.Close()
								output, err := ioutil.ReadAll(httpResponse.Body)
								if err != nil {
									return err
								}
								ocspResponse, err := ocsp.ParseResponse(output, client1_root_cert)
								if err != nil {
									return err
								}
								if ocspResponse.Status == ocsp.Revoked {
									return fmt.Errorf("certificate %s has been revoked by OCSP server %s, refusing connection", c.Subject.SerialNumber, ca_1_ocsp_endpoint)
								}
								// todo, cache response based on ocsp response update interval
								fmt.Println("OCSP verified")
							}
						}
					}
				}
			}
			return nil
		},
	}

	var server *http.Server
	server = &http.Server{
		Addr:      ":8081",
		Handler:   eventsMiddleware(router),
		TLSConfig: tlsConfig,
	}
	http2.ConfigureServer(server, &http2.Server{})
	fmt.Println("Starting Server..")
	err = server.ListenAndServeTLS("", "")

	fmt.Printf("Unable to start Server %v", err)

}
