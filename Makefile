SHELL := /bin/sh

GO ?= go

APP_NAME ?= x509-watch
MAIN_PKG := ./cmd
PKGS := ./...
BIN_DIR ?= bin
BIN := $(BIN_DIR)/$(APP_NAME)
CERT_DIR ?= certs
CERT_CN ?= example.com
CERT_DAYS ?= 365
CERT_GOOD_COUNT ?= 10

COMPOSE_FILE ?= docker-compose.yml

.DEFAULT_GOAL := help

.PHONY: help \
	go-build go-run go-test go-vet go-fmt go-tidy go-cover go-clean \
	certs cert-good cert-expired cert-fake cert-clean \
	docker-up docker-down docker-logs \
	build run test vet fmt tidy cover clean

# ═════ HELP ═════
help:
	@echo "\n[Go]"
	@grep -E '^(go-(build|run|test|vet|fmt|tidy|cover|clean)):' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-14s %s\n", $$1, $$2}'
	@echo "\n[Certificats]"
	@grep -E '^(certs|cert-good|cert-expired|cert-fake|cert-clean):' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-14s %s\n", $$1, $$2}'
	@echo "\n[Docker]"
	@grep -E '^(docker-up|docker-down|docker-logs):' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-14s %s\n", $$1, $$2}'

# ═════ GO ═════
go-build: go-fmt go-vet 
	@mkdir -p $(BIN_DIR)
	$(GO) build -o $(BIN) $(MAIN_PKG)

go-run: 
	$(GO) run $(MAIN_PKG)

go-test:
	$(GO) test -count=1 $(PKGS)

go-vet:
	$(GO) vet $(PKGS)

go-fmt:
	$(GO) fmt $(PKGS)

go-tidy:
	$(GO) mod tidy

go-cover:
	$(GO) test -coverprofile=coverage.out $(PKGS)
	$(GO) tool cover -func=coverage.out

go-clean:
	@rm -rf $(BIN_DIR) coverage.out

build: go-build
run: go-run
test: go-test
vet: go-vet
fmt: go-fmt
tidy: go-tidy
cover: go-cover
clean: go-clean

# ═════ CERTIFICATES ═════
certs: cert-good cert-expired cert-fake cert-short-expiry ## Generates all certs

cert-good:
	@mkdir -p $(CERT_DIR)
	@i=1; while [ $$i -le $(CERT_GOOD_COUNT) ]; do \
		idx=$$(printf "%02d" $$i); \
		cn="$(CERT_CN)-good-$$idx"; \
		openssl req -x509 -newkey rsa:2048 -sha256 -days $(CERT_DAYS) -nodes \
			-keyout $(CERT_DIR)/good-$$idx.key \
			-out $(CERT_DIR)/good-$$idx.pem \
			-subj "/CN=$$cn" \
			-addext "subjectAltName=DNS:$$cn"; \
		i=$$((i+1)); \
	done

cert-expired:
	@ca_dir="$(CERT_DIR)/.ca"; cfg="$(CERT_DIR)/expired-openssl.cnf"; \
	rm -rf $(CERT_DIR)/expired.pem $(CERT_DIR)/expired.key $(CERT_DIR)/expired.csr $$ca_dir; \
	mkdir -p $(CERT_DIR) $$ca_dir; \
	[ -f $$ca_dir/serial ] || echo 01 > $$ca_dir/serial; \
	touch $$ca_dir/index.txt; \
	printf "%s\n" \
	"[ ca ]" \
	"default_ca = CA_default" \
	"" \
	"[ CA_default ]" \
	"dir = $$ca_dir" \
	"database = $$ca_dir/index.txt" \
	"new_certs_dir = $$ca_dir" \
	"serial = $$ca_dir/serial" \
	"private_key = $(CERT_DIR)/expired.key" \
	"certificate = $(CERT_DIR)/expired.pem" \
	"default_md = sha256" \
	"email_in_dn = no" \
	"rand_serial = no" \
	"default_days = 1" \
	"policy = policy_loose" \
	"x509_extensions = usr_cert" \
	"" \
	"[ policy_loose ]" \
	"commonName = supplied" \
	"" \
	"[ usr_cert ]" \
	"basicConstraints = CA:FALSE" \
	"subjectAltName = DNS:$(CERT_CN)-expired" \
	> $$cfg; \
	openssl req -new -newkey rsa:2048 -nodes \
		-config $$cfg \
		-keyout $(CERT_DIR)/expired.key \
		-out $(CERT_DIR)/expired.csr \
		-subj "/CN=$(CERT_CN)-expired"; \
	openssl ca -batch -selfsign \
		-config $$cfg \
		-in $(CERT_DIR)/expired.csr \
		-keyfile $(CERT_DIR)/expired.key \
		-out $(CERT_DIR)/expired.pem \
		-startdate 20200101000000Z -enddate 20200102000000Z; \
	rm -f $(CERT_DIR)/expired.csr $(CERT_DIR)/expired-openssl.cnf

# Generate certs with expiration ((7, 15, 30, 60 days))
cert-short-expiry:
	@mkdir -p $(CERT_DIR)
	@echo "Generating short-expiry certificates in $(CERT_DIR)..."

	openssl req -x509 -newkey rsa:2048 -sha256 -days 7 -nodes \
		-keyout $(CERT_DIR)/soon-7d.key \
		-out $(CERT_DIR)/soon-7d.pem \
		-subj "/CN=$(CERT_CN)-soon-7d" \
		-addext "subjectAltName=DNS:$(CERT_CN)-soon-7d"

	openssl req -x509 -newkey rsa:2048 -sha256 -days 15 -nodes \
		-keyout $(CERT_DIR)/soon-15d.key \
		-out $(CERT_DIR)/soon-15d.pem \
		-subj "/CN=$(CERT_CN)-soon-15d" \
		-addext "subjectAltName=DNS:$(CERT_CN)-soon-15d"

	openssl req -x509 -newkey rsa:2048 -sha256 -days 30 -nodes \
		-keyout $(CERT_DIR)/soon-30d.key \
		-out $(CERT_DIR)/soon-30d.pem \
		-subj "/CN=$(CERT_CN)-soon-30d" \
		-addext "subjectAltName=DNS:$(CERT_CN)-soon-30d"

	openssl req -x509 -newkey rsa:2048 -sha256 -days 60 -nodes \
		-keyout $(CERT_DIR)/soon-60d.key \
		-out $(CERT_DIR)/soon-60d.pem \
		-subj "/CN=$(CERT_CN)-soon-60d" \
		-addext "subjectAltName=DNS:$(CERT_CN)-soon-60d"

cert-fake:
	@mkdir -p $(CERT_DIR)
	openssl genrsa -out $(CERT_DIR)/fake.key 2048
	@printf -- '-----BEGIN CERTIFICATE-----\nNOTACERTIFICATE\n-----END CERTIFICATE-----\n' > $(CERT_DIR)/fake.pem

cert-clean:
	@rm -rf $(CERT_DIR)

# ═════ DOCKER ═════
docker-up:
	docker compose -f $(COMPOSE_FILE) up -d

docker-down:
	docker compose -f $(COMPOSE_FILE) down

docker-logs:
	docker compose -f $(COMPOSE_FILE) logs -f

docker-clean: docker-down
	docker system prune -af
	docker volume prune -af
