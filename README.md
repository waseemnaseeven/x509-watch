# 🔑 x509-watch

An exporter to monitor x509 certificates expiration on your devices with a simple binary, written in Go.

## TODO

- Test more with a Vault agent
- Refacto errors 
- Frontpage ui at the root called web/
- Github actions ci
    - test cert
    - test docker
    - test web npm run test 

## Installation

The best is the docker way cuz you'll have other tools to test (prometheus, alertmanager, vault...)

Follow the Makefile : 
```
make help 

[Go]
  go-build: go-fmt go-vet  
  go-run:        
  go-test:       
  go-vet:        
  go-fmt:        
  go-tidy:       
  go-cover:      
  go-clean:      

[Certificats]
  certs          Generates all certs
  cert-good:     
  cert-expired:  
  cert-fake:     
  cert-clean:    

[Docker]
  docker-up:     
  docker-down:   
  docker-logs:
```


## Usage 

The following metrics are available : 
- `x509_cert_not_before` : Certificate validity start time (unix seconds)
- `x509_cert_not_after` : Certificate expiry time (unix seconds)
- `x509_cert_expired` : 1 if certificate is expired, 0 otherwise
- `x509_cert_expires_in_seconds` : Seconds until certificate expiry (negative if expired)

### Some alerts example w/ prometheus

```
- alert: X509CertificateExpired
    expr: x509_cert_expired == 1
    for: 5m
    labels:
        severity: critical
    annotations:
        summary: X.509 certificate have expired ({{ $labels.common_name }})

- alert: X509CertificateExpiringIn15Days
    expr: x509_cert_expires_in_seconds > 604800
        and x509_cert_expires_in_seconds <= 1296000
    for: 10m
    labels:
        severity: high
    annotations:
        summary: X.509 certificate expiring in 7-15 days ({{ $labels.common_name }})
        description: |
        The X.509 certificate for {{ $labels.common_name }} ({{ $labels.filepath }})
        will expire in between 7 and 15 days.
            VALUE = {{ $value }} seconds until expiry
            LABELS = {{ $labels }}

- alert: X509CertificateExpiringIn30Days
    expr: (x509_cert_not_after - time()) > 0
        and (x509_cert_not_after - time()) <= 2592000
    for: 15m
    labels:
        severity: warning
    annotations:
        summary: X.509 certificate expiring in 15-30 days ({{ $labels.common_name }})
        description: |
        The X.509 certificate for {{ $labels.common_name }} ({{ $labels.filepath }})
        will expire in between 15 and 30 days.
            VALUE = {{ $value }} seconds until expiry
            LABELS = {{ $labels }}
```
