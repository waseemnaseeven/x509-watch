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

COMPOSE_FILE ?= monitoring/docker-compose.yml

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

go-clean: ## Nettoie les artefacts locaux
	@rm -rf $(BIN_DIR) coverage.out

build: go-build
run: go-run
test: go-test
vet: go-vet
fmt: go-fmt
tidy: go-tidy
cover: go-cover
clean: go-clean

# ═════ CERTIFICATS ═════
certs: cert-good cert-expired cert-fake ## Génère tous les certificats de test

cert-good: ## Génère $(CERT_GOOD_COUNT) paires clé/certificat valides
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

cert-expired: ## Génère un certificat déjà expiré
	@mkdir -p $(CERT_DIR)
	openssl req -new -newkey rsa:2048 -nodes \
		-keyout $(CERT_DIR)/expired.key \
		-out $(CERT_DIR)/expired.csr \
		-subj "/CN=$(CERT_CN)-expired"
	openssl x509 -req -in $(CERT_DIR)/expired.csr \
		-signkey $(CERT_DIR)/expired.key \
		-set_serial 01 -sha256 \
		-not_before 20200101000000Z -not_after 20200102000000Z \
		-out $(CERT_DIR)/expired.pem
	@rm -f $(CERT_DIR)/expired.csr

cert-fake: ## Génère un couple clé + fichier PEM invalide (pour tester les erreurs)
	@mkdir -p $(CERT_DIR)
	openssl genrsa -out $(CERT_DIR)/fake.key 2048
	@printf -- '-----BEGIN CERTIFICATE-----\nNOTACERTIFICATE\n-----END CERTIFICATE-----\n' > $(CERT_DIR)/fake.pem

cert-clean: ## Supprime les certificats générés
	@rm -rf $(CERT_DIR)

# ═════ DOCKER ═════
docker-up: ## Lance la stack docker-compose
	docker compose -f $(COMPOSE_FILE) up -d

docker-down: ## Arrête la stack docker-compose
	docker compose -f $(COMPOSE_FILE) down

docker-logs: ## Affiche les logs de la stack
	docker compose -f $(COMPOSE_FILE) logs -f
