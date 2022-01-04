# tlscheck
Simple command line utility to check TLS version and other TCP handshake details

Can be usefull e.g. to check SMTP TLS version

## command line arguments
- -a Server address (-a myserver.com)
- -p Server port (-p 443)
- -i Insecure/accepts any certificate 

## Output
Output is valid yaml formated e.g.
```
tlscheck.exe -a smtp.seznam.cz -p 465
```

```yaml
handshakeOK: true
tlsVersion: TLS 1.3
cipher: TLS_AES_256_GCM_SHA384
chains:
    - - name: www.seznam.cz
        issuer: CN=R3,O=Let's Encrypt,C=US
        validFrom: "2021-12-07 15:01:15"
        validTo: "2022-03-07 15:01:14"
        dns:
            - seznam.cz
            - www.seznam.cz
        issuingCertificateURL:
            - http://r3.i.lencr.org/
        isCA: false
      - name: R3
        issuer: CN=ISRG Root X1,O=Internet Security Research Group,C=US
        validFrom: "2020-09-04 00:00:00"
        validTo: "2025-09-15 16:00:00"
        issuingCertificateURL:
            - http://x1.i.lencr.org/
        isCA: true
      - name: ISRG Root X1
        issuer: CN=ISRG Root X1,O=Internet Security Research Group,C=US
        validFrom: "2015-06-04 11:04:38"
        validTo: "2035-06-04 11:04:38"
        isCA: true
```
