module main

go 1.22.7

toolchain go1.22.9

require (
	github.com/golang/glog v1.2.2
	github.com/salrashid123/go_mtls_scratchpad/grpc/echo v0.0.0
	golang.org/x/net v0.29.0
	google.golang.org/grpc v1.68.0
	google.golang.org/protobuf v1.34.2 // indirect
)

require google.golang.org/grpc/security/advancedtls v1.0.0

require (
	golang.org/x/crypto v0.27.0 // indirect
	golang.org/x/sys v0.25.0 // indirect
	golang.org/x/text v0.18.0 // indirect
	google.golang.org/genproto v0.0.0-20211223182754-3ac035c7e7cb // indirect
)

replace github.com/salrashid123/go_mtls_scratchpad/grpc/echo => ./echo
