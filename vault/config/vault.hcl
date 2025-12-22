ui = true
disable_mlock = true

listener "tcp" {
  address         = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_disable     = true
}

storage "raft" {
  path    = "/vault/data"
  node_id = "vault-1"
}

api_addr     = "http://localhost:8200"
cluster_addr = "http://vault-dev:8201"
