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
CERT_KEY := $(CERT_DIR)/$(APP_NAME).key
CERT_PEM := $(CERT_DIR)/$(APP_NAME).pem
CERT_CRT := $(CERT_DIR)/$(APP_NAME).crt

.DEFAULT_GOAL := help

.PHONY: help build run test vet fmt tidy cover clean pem crt

help: ## Affiche cette aide
	@echo "Commandes disponibles :"
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-10s %s\n", $$1, $$2}'

build: fmt vet ## Compile le binaire dans ./bin
	@mkdir -p $(BIN_DIR)
	$(GO) build -o $(BIN) $(MAIN_PKG)

run: ## Lance l'application en local
	$(GO) run $(MAIN_PKG)

test: ## Exécute la suite de tests
	$(GO) test -count=1 $(PKGS)

vet: ## Analyse statique de base (go vet)
	$(GO) vet $(PKGS)

fmt: ## Formatte le code Go selon gofmt/go fmt
	$(GO) fmt $(PKGS)

tidy: ## Met à jour les dépendances Go modules
	$(GO) mod tidy

cover: ## Génère un rapport de couverture (coverage.out)
	$(GO) test -coverprofile=coverage.out $(PKGS)
	$(GO) tool cover -func=coverage.out

clean: ## Nettoie les artefacts locaux
	@rm -rf $(BIN_DIR) coverage.out

pem: ## Génère une paire clé/certificat auto-signée PEM dans $(CERT_DIR)
	@mkdir -p $(CERT_DIR)
	openssl req -x509 -newkey rsa:2048 -sha256 -days $(CERT_DAYS) -nodes \
		-keyout $(CERT_KEY) -out $(CERT_PEM) -subj "/CN=$(CERT_CN)" \
		-addext "subjectAltName=DNS:$(CERT_CN)"
	@echo "Certificat PEM généré: $(CERT_PEM)"

crt: pem ## Convertit le certificat PEM en DER (.crt) pour tests DER
	openssl x509 -in $(CERT_PEM) -outform der -out $(CERT_CRT)
	@echo "Certificat DER généré: $(CERT_CRT)"
