FROM prom/prometheus:v3.4.0 AS source

FROM ubuntu:24.04

RUN apt update && apt -y upgrade && apt -y install python3 python3-pip && apt -y autoremove && apt clean && rm -rf /var/lib/apt/lists/*

RUN pip3 install --break-system-packages pyyaml

COPY --from=source /bin/prometheus /bin/prometheus
COPY --from=source /bin/promtool /bin/promtool

RUN mkdir -p /mnt/task/prometheus-data && mkdir -p /etc/prometheus

RUN apt update && apt install telnet -y

WORKDIR /srv

COPY start.sh /srv/start.sh
COPY init.py /srv/init.py

RUN chmod +x /srv/start.sh

ENTRYPOINT ["/srv/start.sh"]
