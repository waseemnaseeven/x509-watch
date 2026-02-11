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

# ═══ COLORS ═══
_NO              = \033[0m
_BOLD            = \033[1m
_BLUE            = \033[34m
_CYAN            = \033[36m
_RED             = \033[31m
_YELLOW          = \033[33m
_GREEN           = \033[32m
_GREY            = \033[90m
_ORANGE          = \033[38;5;208m

_OK   = $(_GREEN)✔$(_NO)
_FAIL = $(_RED)✘$(_NO)
_RUN  = $(_CYAN)▶$(_NO)
_INFO = $(_BLUE)ℹ$(_NO)

.DEFAULT_GOAL := help

.PHONY: help \
	go-build go-run go-test go-vet go-fmt go-tidy go-cover go-clean \
	certs cert-good cert-expired cert-fake cert-clean \
	docker-up docker-down docker-logs \
	build run test vet fmt tidy cover clean

# ═════ HELP ═════
help:
	@echo ""
	@echo "$(_BOLD)$(_CYAN)$(APP_NAME)$(_NO) $(_GREY)— available targets$(_NO)"
	@echo ""
	@echo "$(_BOLD)$(_BLUE)  Go$(_NO)"
	@echo "  $(_CYAN)go-build$(_NO)        Build binary to $(BIN)"
	@echo "  $(_CYAN)go-run$(_NO)          Run without building"
	@echo "  $(_CYAN)go-test$(_NO)         Run tests"
	@echo "  $(_CYAN)go-vet$(_NO)          Vet source code"
	@echo "  $(_CYAN)go-fmt$(_NO)          Format source code"
	@echo "  $(_CYAN)go-tidy$(_NO)         Tidy go modules"
	@echo "  $(_CYAN)go-cover$(_NO)        Run tests with coverage"
	@echo "  $(_CYAN)go-clean$(_NO)        Remove build artifacts"
	@echo ""
	@echo "$(_BOLD)$(_ORANGE)  Certificates$(_NO)"
	@echo "  $(_CYAN)certs$(_NO)           Generate all test certs"
	@echo "  $(_CYAN)cert-good$(_NO)       Generate $(CERT_GOOD_COUNT) valid certs"
	@echo "  $(_CYAN)cert-expired$(_NO)    Generate an expired cert"
	@echo "  $(_CYAN)cert-fake$(_NO)       Generate a malformed cert"
	@echo "  $(_CYAN)cert-clean$(_NO)      Remove all certs"
	@echo ""
	@echo "$(_BOLD)$(_YELLOW)  Docker$(_NO)"
	@echo "  $(_CYAN)docker-up$(_NO)       Start containers"
	@echo "  $(_CYAN)docker-down$(_NO)     Stop containers"
	@echo "  $(_CYAN)docker-logs$(_NO)     Tail container logs"
	@echo "  $(_CYAN)docker-clean$(_NO)    Clear containers"
	@echo ""

# ═════ GO ═════
go-build: go-fmt go-vet
	@echo "$(_RUN) Building $(_BOLD)$(APP_NAME)$(_NO)..."
	@mkdir -p $(BIN_DIR)
	@$(GO) build -o $(BIN) $(MAIN_PKG) && \
		echo "$(_OK) Built → $(_BOLD)$(BIN)$(_NO)" || \
		(echo "$(_FAIL) Build failed"; exit 1)

go-run:
	@echo "$(_RUN) Running $(_BOLD)$(APP_NAME)$(_NO)..."
	@$(GO) run $(MAIN_PKG)

go-test:
	@echo "$(_RUN) Running tests..."
	@$(GO) test -count=1 $(PKGS) && \
		echo "$(_OK) All tests passed" || \
		(echo "$(_FAIL) Tests failed"; exit 1)

go-vet:
	@echo "$(_RUN) Vetting..."
	@$(GO) vet $(PKGS) && \
		echo "$(_OK) Vet passed" || \
		(echo "$(_FAIL) Vet failed"; exit 1)

go-fmt:
	@echo "$(_RUN) Formatting..."
	@$(GO) fmt $(PKGS) > /dev/null
	@echo "$(_OK) Formatted"

go-tidy:
	@echo "$(_RUN) Tidying modules..."
	@$(GO) mod tidy
	@echo "$(_OK) Tidy done"

go-cover:
	@echo "$(_RUN) Running coverage..."
	@$(GO) test -coverprofile=coverage.out $(PKGS) && \
		$(GO) tool cover -func=coverage.out && \
		echo "$(_OK) Coverage report generated" || \
		(echo "$(_FAIL) Coverage failed"; exit 1)

go-clean:
	@echo "$(_RUN) Cleaning..."
	@rm -rf $(BIN_DIR) coverage.out
	@echo "$(_OK) Clean"

build: go-build
run: go-run
test: go-test
vet: go-vet
fmt: go-fmt
tidy: go-tidy
cover: go-cover
clean: go-clean

# ═════ CERTIFICATES ═════
certs: cert-good cert-expired cert-fake cert-short-expiry
	@echo "$(_OK) All certificates generated in $(_BOLD)$(CERT_DIR)/$(_NO)"

cert-good:
	@mkdir -p $(CERT_DIR)
	@echo "$(_RUN) Generating $(CERT_GOOD_COUNT) valid certs..."
	@i=1; while [ $$i -le $(CERT_GOOD_COUNT) ]; do \
		idx=$$(printf "%02d" $$i); \
		cn="$(CERT_CN)-good-$$idx"; \
		openssl req -x509 -newkey rsa:2048 -sha256 -days $(CERT_DAYS) -nodes \
			-keyout $(CERT_DIR)/good-$$idx.key \
			-out $(CERT_DIR)/good-$$idx.pem \
			-subj "/CN=$$cn" \
			-addext "subjectAltName=DNS:$$cn" 2>/dev/null; \
		i=$$((i+1)); \
	done
	@echo "$(_OK) $(CERT_GOOD_COUNT) valid certs"

cert-expired:
	@echo "$(_RUN) Generating expired cert..."
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
		-subj "/CN=$(CERT_CN)-expired" 2>/dev/null; \
	openssl ca -batch -selfsign \
		-config $$cfg \
		-in $(CERT_DIR)/expired.csr \
		-keyfile $(CERT_DIR)/expired.key \
		-out $(CERT_DIR)/expired.pem \
		-startdate 20200101000000Z -enddate 20200102000000Z 2>/dev/null; \
	rm -f $(CERT_DIR)/expired.csr $(CERT_DIR)/expired-openssl.cnf
	@echo "$(_OK) Expired cert"

cert-short-expiry:
	@mkdir -p $(CERT_DIR)
	@echo "$(_RUN) Generating short-expiry certs (7d, 15d, 30d, 60d)..."
	@openssl req -x509 -newkey rsa:2048 -sha256 -days 7 -nodes \
		-keyout $(CERT_DIR)/soon-7d.key \
		-out $(CERT_DIR)/soon-7d.pem \
		-subj "/CN=$(CERT_CN)-soon-7d" \
		-addext "subjectAltName=DNS:$(CERT_CN)-soon-7d" 2>/dev/null
	@openssl req -x509 -newkey rsa:2048 -sha256 -days 15 -nodes \
		-keyout $(CERT_DIR)/soon-15d.key \
		-out $(CERT_DIR)/soon-15d.pem \
		-subj "/CN=$(CERT_CN)-soon-15d" \
		-addext "subjectAltName=DNS:$(CERT_CN)-soon-15d" 2>/dev/null
	@openssl req -x509 -newkey rsa:2048 -sha256 -days 30 -nodes \
		-keyout $(CERT_DIR)/soon-30d.key \
		-out $(CERT_DIR)/soon-30d.pem \
		-subj "/CN=$(CERT_CN)-soon-30d" \
		-addext "subjectAltName=DNS:$(CERT_CN)-soon-30d" 2>/dev/null
	@openssl req -x509 -newkey rsa:2048 -sha256 -days 60 -nodes \
		-keyout $(CERT_DIR)/soon-60d.key \
		-out $(CERT_DIR)/soon-60d.pem \
		-subj "/CN=$(CERT_CN)-soon-60d" \
		-addext "subjectAltName=DNS:$(CERT_CN)-soon-60d" 2>/dev/null
	@echo "$(_OK) Short-expiry certs"

cert-fake:
	@mkdir -p $(CERT_DIR)
	@echo "$(_RUN) Generating fake cert..."
	@openssl genrsa -out $(CERT_DIR)/fake.key 2048 2>/dev/null
	@printf -- '-----BEGIN CERTIFICATE-----\nNOTACERTIFICATE\n-----END CERTIFICATE-----\n' > $(CERT_DIR)/fake.pem
	@echo "$(_OK) Fake cert"

cert-clean:
	@echo "$(_RUN) Removing certs..."
	@rm -rf $(CERT_DIR)
	@echo "$(_OK) Certs cleaned"

# ═════ DOCKER ═════
docker-up:
	@echo "$(_RUN) Starting containers..."
	@docker compose -f $(COMPOSE_FILE) up -d
	@echo "$(_OK) Containers up"

docker-down:
	@echo "$(_RUN) Stopping containers..."
	@docker compose -f $(COMPOSE_FILE) down
	@echo "$(_OK) Containers down"

docker-logs:
	@echo "$(_INFO) Tailing logs..."
	@docker compose -f $(COMPOSE_FILE) logs -f

docker-clean: docker-down
	@echo "$(_RUN) Pruning Docker..."
	@docker system prune -af
	@docker volume prune -af
	@echo "$(_OK) Docker cleaned"
