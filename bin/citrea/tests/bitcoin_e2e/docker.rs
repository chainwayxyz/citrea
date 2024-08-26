use super::config::DockerConfig;
use super::node::SpawnOutput;
use super::utils::generate_test_id;
use crate::bitcoin_e2e::node::ContainerSpawnOutput;
use anyhow::{anyhow, Context, Result};
use bollard::container::{Config, NetworkingConfig};
use bollard::image::CreateImageOptions;
use bollard::models::{EndpointSettings, PortBinding};
use bollard::network::CreateNetworkOptions;
use bollard::service::HostConfig;
use bollard::Docker;
use futures::StreamExt;
use std::collections::HashMap;
use std::io::{stdout, Write};

pub struct DockerEnv {
    pub docker: Docker,
    pub network_id: String,
}

impl DockerEnv {
    pub async fn new() -> Result<Self> {
        let docker =
            Docker::connect_with_local_defaults().context("Failed to connect to Docker")?;
        let test_id = generate_test_id();
        let network_id = Self::create_network(&docker, &test_id).await?;
        Ok(Self { docker, network_id })
    }

    async fn create_network(docker: &Docker, test_case_id: &str) -> Result<String> {
        let network_name = format!("test_network_{}", test_case_id);
        let options = CreateNetworkOptions {
            name: network_name,
            check_duplicate: true,
            driver: "bridge".to_string(),
            ..Default::default()
        };

        let id = docker
            .create_network(options)
            .await?
            .id
            .context("Error getting network id")?;
        Ok(id)
    }

    pub async fn spawn(&self, config: DockerConfig) -> Result<SpawnOutput> {
        let exposed_ports: HashMap<String, HashMap<(), ()>> = config
            .ports
            .iter()
            .map(|port| (format!("{}/tcp", port), HashMap::new()))
            .collect();

        let port_bindings: HashMap<String, Option<Vec<PortBinding>>> = config
            .ports
            .iter()
            .map(|port| {
                (
                    format!("{}/tcp", port),
                    Some(vec![PortBinding {
                        host_ip: Some("0.0.0.0".to_string()),
                        host_port: Some(port.to_string()),
                    }]),
                )
            })
            .collect();

        let mut network_config = HashMap::new();
        network_config.insert(self.network_id.clone(), EndpointSettings::default());

        let config = Config {
            image: Some(config.image),
            cmd: Some(config.cmd),
            exposed_ports: Some(exposed_ports),
            host_config: Some(HostConfig {
                port_bindings: Some(port_bindings),
                binds: Some(vec![config.dir]),
                ..Default::default()
            }),
            networking_config: Some(NetworkingConfig {
                endpoints_config: network_config,
            }),
            tty: Some(true),
            ..Default::default()
        };

        let image = config
            .image
            .as_ref()
            .context("Image not specified in config")?;
        self.ensure_image_exists(image).await?;

        // println!("options :{options:?}");
        // println!("config :{config:?}");

        let container = self
            .docker
            .create_container::<String, String>(None, config)
            .await
            .map_err(|e| anyhow!("Failed to create Docker container {e}"))?;

        self.docker
            .start_container::<String>(&container.id, None)
            .await
            .context("Failed to start Docker container")?;

        let inspect_result = self.docker.inspect_container(&container.id, None).await?;
        let ip_address = inspect_result
            .network_settings
            .and_then(|ns| ns.networks)
            .and_then(|networks| {
                networks
                    .values()
                    .next()
                    .and_then(|network| network.ip_address.clone())
            })
            .context("Failed to get container IP address")?;

        Ok(SpawnOutput::Container(ContainerSpawnOutput {
            id: container.id,
            ip: ip_address,
        }))
    }

    async fn ensure_image_exists(&self, image: &str) -> Result<()> {
        let images = self
            .docker
            .list_images::<String>(None)
            .await
            .context("Failed to list Docker images")?;
        if images
            .iter()
            .any(|img| img.repo_tags.contains(&image.to_string()))
        {
            return Ok(());
        }

        println!("Pulling image: {}", image);
        let options = Some(CreateImageOptions {
            from_image: image,
            ..Default::default()
        });

        let mut stream = self.docker.create_image(options, None, None);
        while let Some(result) = stream.next().await {
            match result {
                Ok(info) => {
                    if let (Some(status), Some(progress)) = (info.status, info.progress) {
                        print!("\r{}: {}     ", status, progress);
                        stdout().flush().unwrap();
                    }
                }
                Err(e) => return Err(anyhow::anyhow!("Failed to pull image: {}", e)),
            }
        }
        println!("Image succesfully pulled");

        Ok(())
    }

    pub async fn cleanup(&self) -> Result<()> {
        let containers = self.docker.list_containers::<String>(None).await?;
        for container in containers {
            if let (Some(id), Some(networks)) = (
                container.id,
                container.network_settings.and_then(|ns| ns.networks),
            ) {
                if networks.contains_key(&self.network_id) {
                    self.docker.stop_container(&id, None).await?;
                    self.docker.remove_container(&id, None).await?;
                }
            }
        }

        self.docker.remove_network(&self.network_id).await?;

        Ok(())
    }
}
