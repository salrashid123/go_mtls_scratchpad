
### Using gRPC mtls using AdvancedTLS

* [https://pkg.go.dev/google.golang.org/grpc/security/advancedtls](https://pkg.go.dev/google.golang.org/grpc/security/advancedtls)


##### CRL where the cert isn't revoked

```bash
$ openssl crl -in ../ca1/ca_scratchpad/crl/valid/valid.crl -noout -text
Certificate Revocation List (CRL):
        Version 2 (0x1)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=Collaborator 1, OU=Enterprise, CN=Collaborator 1 Root CA
        Last Update: Nov 25 14:38:42 2024 GMT
        Next Update: Nov 25 14:38:42 2025 GMT
        CRL extensions:
            X509v3 Authority Key Identifier: 
                75:0D:12:CC:DB:33:ED:58:06:8C:AD:ED:0E:9E:2F:00:E9:6F:C1:65
            Authority Information Access: 
                CA Issuers - URI:http://pki.esodemoapp2.com/ca/root-ca.cer
            X509v3 CRL Number: 
                1
No Revoked Certificates.
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:



$ go run server/grpc_server.go  --crl ../ca1/ca_scratchpad/crl/valid/

$ go run client/grpc_client.go  -clientCert ../ca1/revoked.crt  --clientKey ../ca1/revoked.key 
I1125 09:45:35.754324 1165254 grpc_client.go:81] RPC Response: message:"Hello unary RPC msg   from hostname srashid12"
```

##### CRL where the cert is revoked

```bash
$ openssl crl -in ../ca1/ca_scratchpad/crl/revoked/revoked.crl -noout -text
Certificate Revocation List (CRL):
        Version 2 (0x1)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=Collaborator 1, OU=Enterprise, CN=Collaborator 1 Root CA
        Last Update: Nov 25 14:39:17 2024 GMT
        Next Update: Nov 25 14:39:17 2025 GMT
        CRL extensions:
            X509v3 Authority Key Identifier: 
                75:0D:12:CC:DB:33:ED:58:06:8C:AD:ED:0E:9E:2F:00:E9:6F:C1:65
            Authority Information Access: 
                CA Issuers - URI:http://pki.esodemoapp2.com/ca/root-ca.cer
            X509v3 CRL Number: 
                2
Revoked Certificates:
    Serial Number: 04
        Revocation Date: Apr 17 12:10:38 2023 GMT
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:


$ go run server/grpc_server.go  --crl ../ca1/ca_scratchpad/crl/revoked/

$ go run client/grpc_client.go  -clientCert ../ca1/revoked.crt  --clientKey ../ca1/revoked.key
```



