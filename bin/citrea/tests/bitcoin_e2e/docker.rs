use std::collections::HashMap;
use std::io::{stdout, Write};
use std::path::PathBuf;

use super::config::DockerConfig;
use super::node::SpawnOutput;
use super::utils::generate_test_id;
use crate::bitcoin_e2e::node::ContainerSpawnOutput;
use anyhow::{anyhow, Context, Result};
use bollard::container::{Config, LogOutput, LogsOptions, NetworkingConfig};
use bollard::exec::{CreateExecOptions, StartExecOptions};
use bollard::image::CreateImageOptions;
use bollard::models::{EndpointSettings, PortBinding};
use bollard::network::CreateNetworkOptions;
use bollard::service::HostConfig;
use bollard::Docker;
use futures::StreamExt;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::task::JoinHandle;

pub struct DockerEnv {
    pub docker: Docker,
    pub network_id: String,
    pub network_name: String,
}

impl DockerEnv {
    pub async fn new() -> Result<Self> {
        let docker =
            Docker::connect_with_local_defaults().context("Failed to connect to Docker")?;
        let test_id = generate_test_id();
        let (network_id, network_name) = Self::create_network(&docker, &test_id).await?;
        Ok(Self {
            docker,
            network_id,
            network_name,
        })
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

        let container_config = Config {
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

        let image = container_config
            .image
            .as_ref()
            .context("Image not specified in config")?;
        self.ensure_image_exists(image).await?;

        // println!("options :{options:?}");
        // println!("config :{config:?}");

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

    pub async fn restart_bitcoind(
        &self,
        container_id: &str,
        new_config: DockerConfig,
    ) -> Result<()> {
        println!("Restarting bitcoind");
        let stop_options = CreateExecOptions {
            cmd: Some(vec!["bitcoin-cli", "stop"]),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            ..Default::default()
        };
        let exec = self.docker.create_exec(container_id, stop_options).await?;
        let _ = self.docker.start_exec(&exec.id, None).await?;

        // TODO deterministic wait for shutdown
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        // Run bitcoind with updated config
        let mut start_cmd = vec!["bitcoind".to_string()];
        start_cmd.extend(new_config.cmd.clone());

        let start_options = CreateExecOptions {
            cmd: Some(start_cmd),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            ..Default::default()
        };
        let exec = self.docker.create_exec(container_id, start_options).await?;
        let start_exec_options = StartExecOptions {
            detach: true,
            ..Default::default()
        };
        self.docker
            .start_exec(&exec.id, Some(start_exec_options))
            .await?;

        Ok(())
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
            Ok(())
        })
    }
}
