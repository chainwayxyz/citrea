from copy import deepcopy

import yaml


LOCAL = {
    "ENVIRONMENT": "CORE",
    "NET_NAME": "DEV-NET",
    "SERVICE:citrea-sequencer": "host.docker.internal:8001",
    "SERVICE:citrea-full-node": "host.docker.internal:8002",
    "SERVICE:citrea-prover": "host.docker.internal:8003",
    "SERVICE:citrea-light-prover": "host.docker.internal:8004",
}


def main():
    net_name = LOCAL["NET_NAME"]
    env_name = LOCAL["ENVIRONMENT"]

    services = [(k.split(":")[1], v) for k, v in LOCAL.items() if k.startswith("SERVICE:")]

    prometheus_config_yaml = create_prometheus_config(net_name, env_name,  services)

    # print(prometheus_config_yaml)

    with open("/etc/prometheus/prometheus.yml", "w") as f:
        f.write(prometheus_config_yaml)


def create_prometheus_config(net_name: str, env_name: str,  services: list[tuple[str, str]]):
    net_name = net_name.lower()
    env_name = env_name.lower()

    global_config = {
        "scrape_interval": "15s",
        "evaluation_interval": "15s"
    }

    general_relabel_configs = [
        {
            "source_labels": [
                "__address__"
            ],
            "target_label": "net_name",
            "replacement": net_name
        },
        {
            "source_labels": [
                "__address__"
            ],
            "target_label": "env_name",
            "replacement": env_name
        }
    ]

    self_scrape_config = {
        "job_name": "prometheus",
        "static_configs": [
            {
                "targets": [
                    "127.0.0.1:9090"
                ]
            }
        ],
        "relabel_configs": [
            *deepcopy(general_relabel_configs),
            *replacement_builder(".*", "prometheus"),
        ]
    }

    service_grouped = {
        k: [f"{x[1]}" for x in services if x[0] == k]
        for k in set(x[0] for x in services)
    }

    service_configs = [
        {
            "job_name": k,
            "scrape_interval": "1s",
            "static_configs": [
                {
                    "targets": v
                }
            ],
            "relabel_configs": [
                *deepcopy(general_relabel_configs),
                *replacement_builder("(.*)\.?:.*", "$1"),
                *replacement_builder("(.*)\.citrea\.?:.*", "$1"),
                *replacement_builder(f"{env_name}-{net_name}-(.*)\.citrea\.?:.*", "$1"),
            ]
        }
        for k, v in service_grouped.items()
    ]

    scrape_configs = [
        self_scrape_config,
        *service_configs,
    ]


    prometheus_config = {
        "global": global_config,
        "scrape_configs": scrape_configs
    }

    prometheus_config_yaml = yaml.dump(prometheus_config, default_flow_style=False)
    return prometheus_config_yaml


def replacement_builder(regex: str, replacement: str):
    net_name = LOCAL["NET_NAME"].lower()
    env_name = LOCAL["ENVIRONMENT"].lower()

    if "dev" in net_name:
        short_prefix_start = "dn"
    elif "test" in net_name:
        short_prefix_start = "tn"
    elif "main" in net_name:
        short_prefix_start = "mn"
    elif "general" in net_name:
        short_prefix_start = "g"
    else:
        short_prefix_start = "x"

    if "core" in env_name:
        short_prefix_end = "c"
    elif "web" in env_name:
        short_prefix_end = "w"
    elif "pop" in env_name:
        short_prefix_end = "p"
        if "eu" in env_name:
            short_prefix_end = f"{short_prefix_end}eu"
        elif "ap" in env_name:
            short_prefix_end = f"{short_prefix_end}ap"
        else:
            short_prefix_end = f"{short_prefix_end}xx"
    elif "common" in env_name:
        short_prefix_end = "c"
    else:
        short_prefix_end = "x"

    short_prefix = f"{short_prefix_start}{short_prefix_end}"

    return deepcopy([
        {
            "source_labels": [
                "__address__"
            ],
            "regex": regex,
            "target_label": "instance",
            "replacement": f"{short_prefix}-{replacement}",
        },
        {
            "source_labels": [
                "__address__"
            ],
            "regex": regex,
            "target_label": "service_name",
            "replacement": f"{replacement}",
        }
    ])


if __name__ == "__main__":
    main()
