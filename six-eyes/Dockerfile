FROM golang:1.22-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    make \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY go.mod ./
COPY Makefile ./
COPY pkg/ ./pkg/
COPY cmd/ ./cmd/

RUN make build

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    iptables \
    python3 \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/bin/ /app/bin/
COPY scanner/ /app/scanner/
COPY configs/ /app/configs/

EXPOSE 1080 9090
ENTRYPOINT ["/app/bin/six-eyes"]
