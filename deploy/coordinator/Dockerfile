# Control-plane coordinator only. No TUN, no WireGuard, no CAP_NET_ADMIN.
# Overlay VPN packets must never be sent to this container.

FROM rust:bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release -p mynet-coordinator

FROM debian:bookworm-slim
RUN useradd --system --home /var/lib/mynet --create-home mynet
COPY --from=build /src/target/release/mynet-coordinator /usr/local/bin/mynet-coordinator
USER mynet
WORKDIR /var/lib/mynet
EXPOSE 9993/tcp
ENV MYNET_LISTEN=0.0.0.0:9993
ENV MYNET_STATE_PATH=/var/lib/mynet/state.toml
ENV MYNET_NETWORK=mynet
ENTRYPOINT ["/usr/local/bin/mynet-coordinator"]
