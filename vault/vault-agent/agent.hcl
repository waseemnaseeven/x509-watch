# Vault Agent configuration for x509-watch
# Fetches PKI certificates and writes them to disk for DirLoader

vault {
  address = "http://vault:8200"
}

auto_auth {
  method "token_file" {
    config = {
      token_file_path = "/vault/config/vault-token"
    }
  }
}

template_config {
  static_secret_render_interval = "5m"
  exit_on_retry_failure         = true
}

template {
  source      = "/vault/config/cert.tpl"
  destination = "/vault/certs/pki-cert.pem"
  perms       = 0644
}
