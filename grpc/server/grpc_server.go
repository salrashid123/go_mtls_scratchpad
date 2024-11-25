package main

import (
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	echo "github.com/salrashid123/go_mtls_scratchpad/grpc/echo"
	"google.golang.org/grpc/credentials/tls/certprovider/pemfile"
	"google.golang.org/grpc/security/advancedtls"

	log "github.com/golang/glog"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

var (
	tlsCert  = flag.String("tlsCert", "../ca1/tee.crt", "tls Certificate")
	tlsKey   = flag.String("tlsKey", "../ca1/tee.key", "tls Key")
	rootCA   = flag.String("rootCA", "../ca1/root-ca.crt", "CA")
	crl      = flag.String("crl", "../ca1/ca_scratchpad/crl/valid", "crl")
	grpcport = flag.String("grpcport", ":50051", "grpcport")
)

const ()

type contextKey string

func authUnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	//md, _ := metadata.FromIncomingContext(ctx)
	log.Infof("     TLS Peer IP Check")
	var newCtx context.Context
	peer, ok := peer.FromContext(ctx)
	if ok {
		peerIPPort, _, err := net.SplitHostPort(peer.Addr.String())
		if err != nil {
			log.Infof("ERROR:  Could get Remote IP %v", err)
			return nil, status.Errorf(codes.PermissionDenied, fmt.Sprintf("Could not get Remote IP   %v", err))
		}
		log.Infof("PeerIP: %s\n", peerIPPort)
		newCtx = context.WithValue(ctx, contextKey("peerIP"), peerIPPort)
	}

	tlsInfo, ok := peer.AuthInfo.(credentials.TLSInfo)
	if !ok {
		log.Infof("ERROR:  Could get remote TLS")
		return nil, status.Errorf(codes.PermissionDenied, fmt.Sprintf("Could not get remote TLS"))
	}
	ekm, err := tlsInfo.State.ExportKeyingMaterial("my_nonce", nil, 32)
	if err != nil {
		log.Infof("ERROR:  Could getting EKM %v", err)
		return nil, status.Errorf(codes.PermissionDenied, fmt.Sprintf("Could getting EKM   %v", err))
	}
	newCtx = context.WithValue(newCtx, contextKey("ekm"), hex.EncodeToString(ekm))
	return handler(newCtx, req)
}

type Server struct {
	echo.UnimplementedEchoServerServer
}

func NewServer() *Server {
	return &Server{}
}

func (s *Server) SayHelloUnary(ctx context.Context, in *echo.EchoRequest) (*echo.EchoReply, error) {
	ekm := ctx.Value(contextKey("ekm")).(string)
	log.Infof("ekm: %s", ekm)
	log.Infof("Got rpc: --> %s\n", in.Name)
	var h, err = os.Hostname()
	if err != nil {
		log.Fatalf("Unable to get hostname %v", err)
	}
	return &echo.EchoReply{Message: "Hello " + in.Name + "  from hostname " + h}, nil
}

func main() {

	flag.Set("logtostderr", "true")
	flag.Set("stderrthreshold", "INFO")
	flag.Parse()

	lis, err := net.Listen("tcp", *grpcport)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	// server1_cert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
	// if err != nil {
	// 	log.Fatalf("error reading server certs")
	// }

	clientCaCert, err := os.ReadFile(*rootCA)
	if err != nil {
		log.Fatalf("mtls enabled but cannot read mtlsBackendCA cert")
	}
	clientCaCertPool := x509.NewCertPool()
	clientCaCertPool.AppendCertsFromPEM(clientCaCert)

	// tlsConfig := &tls.Config{
	// 	ClientAuth:   tls.RequireAndVerifyClientCert,
	// 	ClientCAs:    clientCaCertPool,
	// 	Certificates: []tls.Certificate{server1_cert},
	// }

	identityOptions := pemfile.Options{
		CertFile:        *tlsCert,
		KeyFile:         *tlsKey,
		RefreshDuration: 1 * time.Minute,
	}
	identityProvider, err := pemfile.NewProvider(identityOptions)
	if err != nil {
		log.Fatalf("pemfile.NewProvider(%v) failed: %v", identityOptions, err)
	}

	defer identityProvider.Close()

	rootOptions := pemfile.Options{
		RootFile:        *rootCA,
		RefreshDuration: 1 * time.Minute,
	}
	rootProvider, err := pemfile.NewProvider(rootOptions)
	if err != nil {
		log.Fatalf("pemfile.NewProvider(%v) failed: %v", rootOptions, err)
	}
	defer rootProvider.Close()

	cw, err := advancedtls.NewFileWatcherCRLProvider(advancedtls.FileWatcherOptions{
		CRLDirectory: *crl,
	})
	if err != nil {
		log.Fatalf("NewCRLProvider(%v) failed: %v", rootOptions, err)
	}
	options := &advancedtls.Options{
		IdentityOptions: advancedtls.IdentityCertificateOptions{
			IdentityProvider: identityProvider,
		},
		RootOptions: advancedtls.RootCertificateOptions{
			RootProvider: rootProvider,
		},
		RequireClientCert: true,
		AdditionalPeerVerification: func(params *advancedtls.HandshakeVerificationInfo) (*advancedtls.PostHandshakeVerificationResults, error) {
			log.Infof("Client common name: %s.\n", params.Leaf.Subject.CommonName)
			return &advancedtls.PostHandshakeVerificationResults{}, nil
		},
		RevocationOptions: &advancedtls.RevocationOptions{
			DenyUndetermined: true,
			CRLProvider:      cw,
		},
		VerificationType: advancedtls.CertAndHostVerification,
	}
	serverTLSCreds, err := advancedtls.NewServerCreds(options)
	if err != nil {
		log.Fatalf("advancedtls.NewServerCreds(%v) failed: %v", options, err)
	}

	sopts := []grpc.ServerOption{}
	//sopts = append(sopts, grpc.Creds(credentials.NewTLS(tlsConfig)), grpc.UnaryInterceptor(authUnaryInterceptor))
	sopts = append(sopts, grpc.Creds(serverTLSCreds), grpc.UnaryInterceptor(authUnaryInterceptor))
	s := grpc.NewServer(sopts...)
	srv := NewServer()
	echo.RegisterEchoServerServer(s, srv)
	reflection.Register(s)
	log.Info("Starting Server...")
	s.Serve(lis)

}
