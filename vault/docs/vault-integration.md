# Vault PKI Integration

Monitor X.509 certificates issued by HashiCorp Vault's PKI secrets engine.

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│                 │    │                 │    │                 │
│      Vault      │◄───│  Vault Agent    │───►│   x509-watch    │
│   (PKI Engine)  │    │  (sidecar)      │    │   (DirLoader)   │
│                 │    │                 │    │                 │
└─────────────────┘    └────────┬────────┘    └────────┬────────┘
                                │                      │
                                ▼                      ▼
                       /vault/certs/           curl :9101/metrics
                       pki-cert.pem
```

**Flow:**
1. Vault Agent authenticates to Vault (dev token)
2. Agent renders template, issuing cert via `pki/issue/test-cert`
3. Agent writes certificate to shared volume `/vault/certs/`
4. x509-watch `DirLoader` reads certificates from `/certs/` (mounted volume)
5. Metrics exposed at `:9101/metrics`

## Quick Start

### 1. Start the stack

```bash
docker compose up -d
```

### 2. Configure Vault PKI

```bash
# Set environment
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root

# Run setup script
./vault/vault-pki-setup.sh
```

### 3. Provide token to Vault Agent

The Vault Agent needs the dev token to authenticate:

```bash
# Create token file in the vault-token volume
docker compose exec vault-agent sh -c 'echo "root" > /vault/token/vault-token'

# Restart Vault Agent to pick up the token
docker compose restart vault-agent
```

### 4. Verify

```bash
# Check Vault Agent logs
docker compose logs vault-agent

# Check certificates were written
docker compose exec vault-agent ls -la /vault/certs/

# Check x509-watch metrics
curl -s localhost:9101/metrics | grep x509_cert
```

Expected output:
```
x509_cert_not_after{common_name="monitored.example.com",filepath="/certs/pki-cert.pem",issuer="x509-watch-ca"} 1.7380512e+09
x509_cert_expires_in_seconds{common_name="monitored.example.com",filepath="/certs/pki-cert.pem",issuer="x509-watch-ca"} 86400
```

## Configuration

### Vault Agent (`deploy/vault-agent/agent.hcl`)

| Setting | Description |
|---------|-------------|
| `vault.address` | Vault server URL |
| `auto_auth.method` | Authentication method (token_file for dev) |
| `template.source` | Template file path |
| `template.destination` | Output certificate path |
| `template_config.static_secret_render_interval` | Re-render interval |

### Certificate Template (`deploy/vault-agent/cert.tpl`)

Modify to change the issued certificate:

```hcl
{{- with secret "pki/issue/test-cert" "common_name=myapp.example.com" "ttl=48h" -}}
{{ .Data.certificate }}
{{ .Data.issuing_ca }}
{{- end -}}
```

### Multiple Certificates

Add additional templates to `agent.hcl`:

```hcl
template {
  source      = "/vault/config/app1.tpl"
  destination = "/vault/certs/app1.pem"
}

template {
  source      = "/vault/config/app2.tpl"
  destination = "/vault/certs/app2.pem"
}
```

## Troubleshooting

### Vault Agent exits immediately

Check logs:
```bash
docker compose logs vault-agent
```

Common causes:
- Token file missing: Create `/vault/token/vault-token` with valid token
- Vault not ready: Ensure Vault healthcheck passes
- PKI not configured: Run `./scripts/vault-pki-setup.sh`

### No metrics for PKI certs

1. Verify cert exists:
   ```bash
   docker compose exec vault-agent cat /vault/certs/pki-cert.pem
   ```

2. Check x509-watch can read:
   ```bash
   docker compose exec x509-watch ls -la /certs/
   ```

3. Check x509-watch logs:
   ```bash
   docker compose logs x509-watch
   ```

### Certificate parse errors

If the template output is malformed, check:
- Template syntax in `cert.tpl`
- PKI role exists: `vault read pki/roles/test-cert`
- Role allows the common_name being requested
