


https://github.com/GoogleCloudPlatform/gcp-ca-service-ocsp

wireshark trace.cap -otls.keylog_file:keylog.log

https://github.com/salrashid123/envoy_mtls?tab=readme-ov-file#ca-setup



```bash
openssl ocsp -index ca_scratchpad/ca/root-ca/db/root-ca.db -port 9999 \
 -rsigner ca_scratchpad/certs/ocsp.crt -rkey ca_scratchpad/certs/ocsp.key \
  -CA ca_scratchpad/ca/root-ca.crt -text -ndays 3500
```


```bash
$ openssl crl -in  ca_scratchpad/crl/root-ca-empty-valid.crl -noout -text
Certificate Revocation List (CRL):
        Version 2 (0x1)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=Google, OU=Enterprise, CN=Single Root CA
        Last Update: Nov 16 14:02:04 2024 GMT
        Next Update: Feb  2 14:02:04 2033 GMT
        CRL extensions:
            X509v3 Authority Key Identifier: 
                33:1A:81:E6:00:5B:F5:6E:17:DE:78:9B:32:F7:D1:A5:0B:E1:2E:31
            Authority Information Access: 
                CA Issuers - URI:http://pki.esodemoapp2.com/ca/root-ca.cer
            X509v3 CRL Number: 
                4
No Revoked Certificates.
    Signature Algorithm: sha256WithRSAEncryption


$ openssl crl -in  ca_scratchpad/crl/root-ca-http-revoked.crl -noout -text
Certificate Revocation List (CRL):
        Version 2 (0x1)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=Google, OU=Enterprise, CN=Single Root CA
        Last Update: Nov 16 14:22:12 2024 GMT
        Next Update: Feb  2 14:22:12 2033 GMT
        CRL extensions:
            X509v3 Authority Key Identifier: 
                33:1A:81:E6:00:5B:F5:6E:17:DE:78:9B:32:F7:D1:A5:0B:E1:2E:31
            Authority Information Access: 
                CA Issuers - URI:http://pki.esodemoapp2.com/ca/root-ca.cer
            X509v3 CRL Number: 
                5
Revoked Certificates:
    Serial Number: 02
        Revocation Date: Nov 16 14:22:02 2024 GMT
```


