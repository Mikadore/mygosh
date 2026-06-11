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

ENV MYGOSH_HOME=/var/lib/mygosh
ENV MYGOSH_CONFIG_FILE=mygosh.toml
ENV MYGOSH_LISTEN_HOST=0.0.0.0

WORKDIR ${MYGOSH_HOME}

RUN apt-get update \
	&& apt-get install -y --no-install-recommends bash ca-certificates \
	&& rm -rf /var/lib/apt/lists/* \
	&& mkdir -p /usr/share/mygosh /docker-entrypoint.d

COPY --from=builder /out/mygosh /usr/local/bin/mygosh
COPY mygosh.toml /usr/share/mygosh/mygosh.toml
COPY docker/server/entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY docker/server/entrypoint.d/ /docker-entrypoint.d/

RUN chmod +x /usr/local/bin/docker-entrypoint.sh /docker-entrypoint.d/*.sh

EXPOSE 42022

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["mygosh", "server"]
