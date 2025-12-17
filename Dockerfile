# syntax=docker/dockerfile:1.7

ARG GO_VERSION=1.22
FROM golang:${GO_VERSION}-alpine AS builder

WORKDIR /src
RUN apk add --no-cache ca-certificates  build-base
ENV GOTOOLCHAIN=auto

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG REVISION=unknown
ENV CGO_ENABLED=0

RUN go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/x509-watch ./cmd

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /out/x509-watch /usr/local/bin/x509-watch
EXPOSE 9101
ENTRYPOINT ["/usr/local/bin/x509-watch"]
