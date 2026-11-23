FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY static ./static
COPY src ./src
ARG CARGO_PROFILE=release
ARG CARGO_BUILD_JOBS
RUN set -eu; \
    jobs="${CARGO_BUILD_JOBS:-$(nproc)}"; \
    echo "cargo profile=${CARGO_PROFILE} jobs=${jobs}"; \
    mkdir -p /out; \
    if [ "$CARGO_PROFILE" = "release" ]; then \
      cargo build --release --jobs "$jobs"; \
      cp target/release/opinionated-dns /out/opinionated-dns; \
    else \
      cargo build --jobs "$jobs"; \
      cp target/debug/opinionated-dns /out/opinionated-dns; \
    fi

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/opinionated-dns /usr/local/bin/opinionated-dns
ENTRYPOINT ["/usr/local/bin/opinionated-dns"]
CMD ["/config.toml"]
