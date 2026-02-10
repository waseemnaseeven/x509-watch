#!/usr/bin/env bash
#
# Setup Vault PKI secrets engine for x509-watch testing
# Requires: VAULT_ADDR and VAULT_TOKEN environment variables
# Idempotent: safe to run multiple times
#
set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-root}"

export VAULT_ADDR VAULT_TOKEN

echo "==> Configuring Vault PKI at ${VAULT_ADDR}"

# Check if PKI role already exists (idempotency check)
if vault read pki/roles/test-cert >/dev/null 2>&1; then
    echo "==> PKI already configured, skipping setup"
    exit 0
fi

# Enable PKI secrets engine
echo "==> Enabling PKI secrets engine..."
vault secrets enable pki 2>/dev/null || echo "    PKI already enabled"

# Tune PKI for 1-year max TTL
vault secrets tune -max-lease-ttl=8760h pki

# Generate internal root CA
echo "==> Generating root CA..."
vault write -field=certificate pki/root/generate/internal \
    common_name="x509-watch-ca" \
    issuer_name="root-ca" \
    ttl=8760h > /dev/null

# Configure CA and CRL URLs
vault write pki/config/urls \
    issuing_certificates="${VAULT_ADDR}/v1/pki/ca" \
    crl_distribution_points="${VAULT_ADDR}/v1/pki/crl"

# Create role for issuing certificates
echo "==> Creating PKI role 'test-cert'..."
vault write pki/roles/test-cert \
    allowed_domains="example.com,local" \
    allow_subdomains=true \
    allow_bare_domains=true \
    max_ttl=72h

# Issue a sample certificate
echo "==> Issuing sample certificate..."
vault write -format=json pki/issue/test-cert \
    common_name="test.example.com" \
    ttl=24h | jq -r '.data.certificate' > /tmp/test-cert.pem

echo "==> PKI setup complete!"
echo "    Root CA:     x509-watch-ca"
echo "    Role:        test-cert"
echo "    Domains:     *.example.com, *.local"
echo "    Sample cert: /tmp/test-cert.pem"
