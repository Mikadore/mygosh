# syntax=docker/dockerfile:1.7

ARG GO_VERSION=1.26.2
ARG BUF_VERSION=v1.70.0

FROM golang:${GO_VERSION}-bookworm AS builder

ARG BUF_VERSION

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

RUN GOBIN=/usr/local/bin go install github.com/bufbuild/buf/cmd/buf@${BUF_VERSION}

COPY buf.yaml buf.gen.yaml buf.lock ./
COPY proto ./proto
COPY bin ./bin
COPY app ./app
COPY lib ./lib

RUN buf generate
RUN go build -o /out/mygosh ./bin

FROM debian:bookworm-slim AS runtime

WORKDIR /workspace

RUN apt-get update \
	&& apt-get install -y --no-install-recommends bash ca-certificates \
	&& rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/mygosh /usr/local/bin/mygosh
COPY mygosh-server.toml ./mygosh-server.toml

EXPOSE 42022

CMD ["mygosh", "server"]
