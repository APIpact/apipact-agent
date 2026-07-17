# Multi-stage build producing a minimal image with the supervisor + worker.
# In containers, set update.mode = "external" (the default for image installs):
# the supervisor supervises the worker and restarts it on crash, while "update"
# is a new image tag pulled by your orchestrator (k8s/compose/watchtower).

FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
ENV CGO_ENABLED=0
RUN set -eux; \
    LD="-s -w \
      -X github.com/APIpact/apipact-agent/internal/version.Version=${VERSION} \
      -X github.com/APIpact/apipact-agent/internal/version.Commit=${COMMIT} \
      -X github.com/APIpact/apipact-agent/internal/version.Date=${DATE}"; \
    go build -trimpath -ldflags "$LD" -o /out/apipact-supervisor ./cmd/supervisor; \
    go build -trimpath -ldflags "$LD" -o /out/apipact-worker ./cmd/worker; \
    go build -trimpath -ldflags "$LD" -o /out/agentctl ./cmd/agentctl

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/apipact-supervisor /usr/local/bin/apipact-supervisor
COPY --from=build /out/apipact-worker /usr/local/bin/apipact-worker
COPY --from=build /out/agentctl /usr/local/bin/agentctl
# Config is mounted at /etc/apipact/agent.json (0600). Health on loopback.
ENV APIPACT_CONFIG=/etc/apipact/agent.json \
    APIPACT_WORKER_BIN=/usr/local/bin/apipact-worker \
    APIPACT_HEALTH_ADDR=127.0.0.1:9099
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/apipact-supervisor"]
