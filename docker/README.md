# Guide to run prometheus and grafana

## Guide for external users who want to see grafana dashboards next to their nodes
1) go into `<project_dir>/docker directory
2) run: `docker compose -f docker-compose.telemetry.user.yaml up`
3) go to `localhost:3000` for grafana
4) In `<project_dir>/resources/grafana/user` copy the json of any node you want to see and import it in to your grafana

PS: Do not forget to add telemetry config to your `rollup_config.toml`


## Guide for citrea developers to update grafana dashboard locally then update it on production
1) Go into `<project_dir>/docker` directory
2) to run prometheus and grafana run: `docker compose -f docker-compose.telemetry.yaml up`
3) go to localhost:3000 and do the updates to the dashboard

### To update prod dashboard
4) When exporting dashboard select export as code -> classic and disable `Export for sharing externally` as the local data source uid is the same with prod
5) To update the prod dashboard click edit then go to settings -> `JSON Model` and paste the new json.
6) Update the prod dashboard under `resources/grafana/prod`

### To Update user dashboards
7) After updating the prod dashboard invoke the python script:
```
$ python ./resource/grafana/remove_labels.py ./resources/grafana/prod/<node_type>.dashboard.json > ./resources/grafana/user/<node_type>.dashboard.json 
```

8) Run the prometheus server in user mode and import the newly generated user dashboard to check all is well
