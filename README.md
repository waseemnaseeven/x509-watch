# 🔑 x509-watch

An exporter to monitor x509 certificates expiration on your devices with a simple binary, written in Go.

## TODO

- [x] Test with a Vault agent
- [ ] Refacto errors
- [ ] Frontpage UI at the root called `web/`

## Installation

The best is the docker way cuz you'll have other tools to test (prometheus, alertmanager, vault...)

Follow the Makefile : 
```
make help 

x509-watch — available targets

  [Go]
  go-build        Build binary to bin/x509-watch
  go-run          Run without building
  go-test         Run tests
  go-vet          Vet source code
  go-fmt          Format source code
  go-tidy         Tidy go modules
  go-cover        Run tests with coverage
  go-clean        Remove build artifacts

  [Certificates]
  certs           Generate all test certs
  cert-good       Generate 10 valid certs
  cert-expired    Generate an expired cert
  cert-fake       Generate a malformed cert
  cert-clean      Remove all certs

  [Docker]
  docker-up       Start containers
  docker-down     Stop containers
  docker-logs     Tail container logs

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
