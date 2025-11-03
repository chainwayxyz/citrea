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
ARG NETWORK
ENV NETWORK=$NETWORK
ARG SERVICE_TYPE
ENV SERVICE_TYPE=$SERVICE_TYPE

WORKDIR /srv/app

COPY ./devops/dockers/citrea/genesis/ ./genesis/
COPY ./devops/dockers/citrea/citrea citrea
COPY ./devops/dockers/citrea/r0vm /usr/local/bin/
COPY ./devops/dockers/citrea/citrea-cli /usr/local/bin/
COPY ./devops/dockers/citrea/entrypoint.sh entrypoint.sh

RUN chmod +x entrypoint.sh citrea /usr/local/bin/citrea-cli /usr/local/bin/r0vm

ENTRYPOINT ["./entrypoint.sh"]