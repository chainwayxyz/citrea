FROM debian:bookworm-slim
RUN \
  apt-get update \
  && apt-get -y install gettext-base \
  && apt-get clean \
  && apt-get install -y --no-install-recommends ca-certificates \
  && update-ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /srv/app
COPY genesis/ ./genesis/
COPY citrea citrea

ENTRYPOINT ["./citrea"]
CMD ["--da-layer", "bitcoin", "--genesis-paths", "genesis", "--network", "testnet"]