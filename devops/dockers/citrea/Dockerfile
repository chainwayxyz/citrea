FROM debian:bookworm-slim as prod
RUN \
  apt-get update \
  && apt-get -y install gettext-base \
  && apt-get clean \
  && apt-get install -y --no-install-recommends ca-certificates \
  && update-ca-certificates \
  && rm -rf /var/lib/apt/lists/*

ARG DA_LAYER
ENV DA_LAYER=$DA_LAYER
ARG GENESIS_PATH
ENV GENESIS_PATH=$GENESIS_PATH
ARG SERVICE_TYPE
ENV SERVICE_TYPE=$SERVICE_TYPE

WORKDIR /srv/app

COPY genesis/ ./genesis/
COPY citrea citrea
COPY r0vm /usr/local/bin/
COPY citrea-cli /usr/local/bin/
COPY entrypoint.sh entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]