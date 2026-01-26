FROM debian:trixie-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    update-ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY citrea ./citrea
COPY entrypoint.sh ./entrypoint.sh
RUN chmod +x ./entrypoint.sh ./citrea

# Network defaults
ENV NETWORK=mainnet
ENV DA_LAYER=bitcoin

# Genesis path - user mounts genesis files here
ENV GENESIS_PATH=/app/genesis

# Storage defaults
ENV STORAGE_PATH=/mnt/task/citrea-db

# RPC defaults
ENV RPC_BIND_HOST=0.0.0.0
ENV RPC_BIND_PORT=8080

EXPOSE 8080

ENTRYPOINT ["./entrypoint.sh"]
