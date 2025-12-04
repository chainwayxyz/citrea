# Guide to run prometheus and grafana locally that is identical to production grafana

1) Go into `<project_dir>/docker/prometheus` directory
2) In `init.py` adjust the dictionary `LOCAL` to your needs (telemetry ports)
3) run `docker build -t local-prometheus .`
4) run `cd ../`
5) to run prometheus and grafana run: `docker compose -f docker-compose.telemetry.yaml up`
6) go to localhost:3000 and do the updates to the dashboard

# To update prod dashboard
7) When exporting dashboard select export as code -> classic and disable `Export for sharing externally` as the local data source uid is the same with prod
8) To update the prod dashboard click edit then go to settings -> `JSON Model` and paste the new json.