package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"os"
	"time"

	echo "github.com/salrashid123/go_mtls_scratchpad/grpc/echo"

	log "github.com/golang/glog"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const ()

var ()

func main() {

	address := flag.String("host", "localhost:50051", "host:port of gRPC server")
	rootCert := flag.String("tlsCert", "../ca1/root-ca.crt", "tls root Certificate")
	clientCert := flag.String("clientCert", "../ca1/client.crt", "tls client Certificate")

	clientKey := flag.String("clientKey", "../ca1/client.key", "tls client key")

	serverName := flag.String("servername", "tee.collaborator1.com", "ServerName for server")
	repeat := flag.Int("repeat", 1, "Number of Unary Requests to send")

	flag.Set("logtostderr", "true")
	flag.Set("stderrthreshold", "INFO")
	flag.Parse()

	var err error
	var conn *grpc.ClientConn

	rootCAs := x509.NewCertPool()

	pem, err := os.ReadFile(*rootCert)
	if err != nil {
		log.Fatalf("failed to load root CA certificates  error=%v", err)
	}
	if !rootCAs.AppendCertsFromPEM(pem) {
		log.Fatalf("no root CA certs parsed from file ")
	}

	ccerts, err := tls.LoadX509KeyPair(*clientCert, *clientKey)
	if err != nil {
		log.Fatalf("error loading keypair: %v", err)
	}
	tlsCfg := &tls.Config{
		RootCAs:      rootCAs,
		ServerName:   *serverName,
		Certificates: []tls.Certificate{ccerts},
	}

	ce := credentials.NewTLS(tlsCfg)

	conn, err = grpc.Dial(*address, grpc.WithTransportCredentials(ce))

	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	c := echo.NewEchoServerClient(conn)
	ctx := context.Background()

	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	for i := 0; i < *repeat; i++ {
		r, err := c.SayHelloUnary(ctx, &echo.EchoRequest{Name: "unary RPC msg "})
		if err != nil {
			log.Fatalf("could not greet: %v", err)
		}
		log.Infof("RPC Response: %v\n", r)
	}
}
