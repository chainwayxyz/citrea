#!/bin/bash
set -e

python3 ./init.py


# run with server mode
/bin/prometheus \
  --config.file=/etc/prometheus/prometheus.yml \
  --storage.tsdb.path=/mnt/task/prometheus-data \
  --web.external-url= \
  --web.page-title="DEV-NET CORE Prometheus" \
  --web.enable-lifecycle \
  --web.enable-admin-api \
  --storage.tsdb.retention.time=30d
