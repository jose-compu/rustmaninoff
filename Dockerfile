# syntax=docker/dockerfile:1
# Default: pack GitHub Release binaries (seconds). Full compile: --build-arg BUILD_MODE=source

ARG BUILD_MODE=release

FROM rust:1-bookworm AS build-source
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p rustmaninoff \
    && strip target/release/rustmaninoff \
    && mkdir -p /out \
    && cp target/release/rustmaninoff /out/rustmaninoff

FROM debian:bookworm-slim AS build-release
ARG TARGETARCH
ARG VERSION=0.4.1
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) target=x86_64-unknown-linux-gnu ;; \
      arm64) target=aarch64-unknown-linux-gnu ;; \
      *) echo "unsupported TARGETARCH=$TARGETARCH" >&2; exit 1 ;; \
    esac; \
    asset="rustmaninoff-${target}.tar.gz"; \
    url="https://github.com/jose-compu/rustmaninoff/releases/download/v${VERSION}/${asset}"; \
    echo "Fetching ${url}"; \
    # Retry briefly in case the image build starts just as assets finish uploading.
    i=0; \
    until curl -fsSL -o /tmp/rustmaninoff.tar.gz "$url"; do \
      i=$((i+1)); \
      if [ "$i" -ge 30 ]; then \
        echo "failed to download ${url}" >&2; \
        exit 1; \
      fi; \
      echo "retry ${i}/30…"; \
      sleep 10; \
    done; \
    mkdir -p /out; \
    tar -xzf /tmp/rustmaninoff.tar.gz -C /out; \
    chmod 755 /out/rustmaninoff; \
    /out/rustmaninoff --version

FROM build-${BUILD_MODE} AS build

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home --home-dir /src rustmaninoff
COPY --from=build /out/rustmaninoff /usr/local/bin/rustmaninoff
WORKDIR /src
USER rustmaninoff
HEALTHCHECK CMD rustmaninoff --version
ENTRYPOINT ["rustmaninoff"]
CMD ["scan", "."]
