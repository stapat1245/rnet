# Optional two-peer UDP relay. Opaque packets only. Not the coordinator.

FROM rust:bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release -p mynet-relay

FROM debian:bookworm-slim
RUN useradd --system --home /var/lib/mynet --create-home mynet
COPY --from=build /src/target/release/mynet-relay /usr/local/bin/mynet-relay
USER mynet
WORKDIR /var/lib/mynet
EXPOSE 9994/udp
ENV MYNET_LISTEN=0.0.0.0:9994
ENTRYPOINT ["/usr/local/bin/mynet-relay"]
