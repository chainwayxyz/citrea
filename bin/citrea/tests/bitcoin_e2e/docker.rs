use std::collections::{HashMap, HashSet};
use std::io::{stdout, Write};
use std::path::PathBuf;

use super::config::DockerConfig;
use super::node::SpawnOutput;
use super::utils::generate_test_id;
use crate::bitcoin_e2e::node::ContainerSpawnOutput;
use anyhow::{anyhow, Context, Result};
use bollard::container::{Config, LogOutput, LogsOptions, NetworkingConfig};
use bollard::image::CreateImageOptions;
use bollard::models::{EndpointSettings, Mount, PortBinding};
use bollard::network::CreateNetworkOptions;
use bollard::secret::MountTypeEnum;
use bollard::service::HostConfig;
use bollard::volume::CreateVolumeOptions;
use bollard::Docker;
use futures::StreamExt;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::task::JoinHandle;

pub struct DockerEnv {
    pub docker: Docker,
    pub network_id: String,
    pub network_name: String,
    id: String,
    volumes: HashSet<String>,
}

impl DockerEnv {
    pub async fn new() -> Result<Self> {
        let docker =
            Docker::connect_with_local_defaults().context("Failed to connect to Docker")?;
        let test_id = generate_test_id();
        let (network_id, network_name) = Self::create_network(&docker, &test_id).await?;
        let volumes = Self::create_volumes(&docker, &test_id).await?;

        Ok(Self {
            docker,
            network_id,
            network_name,
            id: test_id,
            volumes,
        })
    }

    async fn create_volumes(docker: &Docker, test_case_id: &str) -> Result<HashSet<String>> {
        let mut volumes = HashSet::new();

        for name in ["bitcoin"] {
            let volume_name = format!("{name}-{test_case_id}");
            docker
                .create_volume(CreateVolumeOptions {
                    name: volume_name.clone(),
                    driver: "local".to_string(),
                    driver_opts: HashMap::new(),
                    labels: HashMap::new(),
                })
                .await?;

            volumes.insert(volume_name);
        }

        Ok(volumes)
    }

    async fn create_network(docker: &Docker, test_case_id: &str) -> Result<(String, String)> {
        let network_name = format!("test_network_{}", test_case_id);
        let options = CreateNetworkOptions {
            name: network_name.clone(),
            check_duplicate: true,
            driver: "bridge".to_string(),
            ..Default::default()
        };

        let id = docker
            .create_network(options)
            .await?
            .id
            .context("Error getting network id")?;
        Ok((id, network_name))
    }

    pub async fn spawn(&self, config: DockerConfig) -> Result<SpawnOutput> {
        println!("Spawning docker with config {config:#?}");
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

        let volume_name = format!("{}-{}", config.volume.name, self.id);
        let mount = Mount {
            target: Some(config.volume.target.clone()),
            source: Some(volume_name),
            typ: Some(MountTypeEnum::VOLUME),
            ..Default::default()
        };

        let container_config = Config {
            image: Some(config.image),
            cmd: Some(config.cmd),
            exposed_ports: Some(exposed_ports),
            host_config: Some(HostConfig {
                port_bindings: Some(port_bindings),
                // binds: Some(vec![config.dir]),
                mounts: Some(vec![mount]),
                ..Default::default()
            }),
            networking_config: Some(NetworkingConfig {
                endpoints_config: network_config,
            }),
            tty: Some(true),
            ..Default::default()
        };

        let image = container_config
            .image
            .as_ref()
            .context("Image not specified in config")?;
        self.ensure_image_exists(image).await?;

        // println!("options :{options:?}");
        // println!("config :{container_config:?}");

        let container = self
            .docker
            .create_container::<String, String>(None, container_config)
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

        // Extract container logs to host
        // This spawns a background task to continuously stream logs from the container.
        // The task will run until the container is stopped or removed during cleanup.
        Self::extract_container_logs(self.docker.clone(), container.id.clone(), config.log_path);

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
                if networks.contains_key(&self.network_name) {
                    self.docker.stop_container(&id, None).await?;
                    self.docker.remove_container(&id, None).await?;
                }
            }
        }

        self.docker.remove_network(&self.network_name).await?;

        for volume_name in &self.volumes {
            self.docker.remove_volume(volume_name, None).await?;
        }

        Ok(())
    }

    fn extract_container_logs(
        docker: Docker,
        container_id: String,
        log_path: PathBuf,
    ) -> JoinHandle<Result<()>> {
        tokio::spawn(async move {
            if let Some(parent) = log_path.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .context("Failed to create log directory")?;
            }
            let mut log_file = File::create(log_path)
                .await
                .context("Failed to create log file")?;
            let mut log_stream = docker.logs::<String>(
                &container_id,
                Some(LogsOptions {
                    follow: true,
                    stdout: true,
                    stderr: true,
                    ..Default::default()
                }),
            );

            while let Some(Ok(log_output)) = log_stream.next().await {
                let log_line = match log_output {
                    LogOutput::Console { message } | LogOutput::StdOut { message } => message,
                    _ => continue,
                };
                log_file
                    .write_all(&log_line)
                    .await
                    .context("Failed to write log line")?;
            }
            println!("Done extracing logs");
            Ok(())
        })
    }
}
