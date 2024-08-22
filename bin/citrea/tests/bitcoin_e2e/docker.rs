use std::collections::HashMap;
use std::path::PathBuf;

use super::config::DockerConfig;
use super::node::SpawnOutput;
use anyhow::{anyhow, Context, Result};
use bollard::container::{Config, CreateContainerOptions};
use bollard::image::CreateImageOptions;
use bollard::models::PortBinding;
use bollard::secret::HostConfigLogConfig;
use bollard::service::HostConfig;
use bollard::Docker;
use citrea_sequencer::SequencerConfig;
use futures::StreamExt;
use std::io::{stdout, Write};

pub async fn spawn_docker(config: DockerConfig) -> Result<SpawnOutput> {
    let docker = Docker::connect_with_local_defaults().context("Failed to connect to Docker")?;

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

    let options: CreateContainerOptions<String> = CreateContainerOptions {
        ..Default::default()
    };

    let config = Config {
        image: Some(config.image),
        cmd: Some(config.cmd),
        exposed_ports: Some(exposed_ports),
        host_config: Some(HostConfig {
            port_bindings: Some(port_bindings),
            binds: Some(vec![format!(
                "{}:/bitcoin/data",
                config.dir.display().to_string()
            )]),
            ..Default::default()
        }),
        tty: Some(true),
        ..Default::default()
    };

    let image = config
        .image
        .as_ref()
        .context("Image not specified in config")?;
    ensure_image_exists(&docker, image).await?;

    println!("options :{options:?}");
    println!("config :{config:?}");

    let container = docker
        .create_container::<String, String>(None, config)
        .await
        .map_err(|e| anyhow!("Failed to create Docker container {e}"))?;

    docker
        .start_container::<String>(&container.id, None)
        .await
        .context("Failed to start Docker container")?;

    Ok(SpawnOutput::ContainerId(container.id))
}

async fn ensure_image_exists(docker: &Docker, image: &str) -> Result<()> {
    let images = docker
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

    let mut stream = docker.create_image(options, None, None);
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
