
use std::error::Error;
use std::time::Duration;

use futures::prelude::*;
use libp2p::swarm::SwarmEvent;
use libp2p::{noise, ping, tcp, yamux, Multiaddr};
use tracing_subscriber::EnvFilter;

pub struct Network;

impl Network {
    pub async fn run() -> Result<(), Box<dyn Error>> {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .try_init();

        let mut swarm = libp2p::SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(|_| ping::Behaviour::default())?
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(u64::MAX)))
            .build();

        // Tell the swarm to listen on all interfaces and a random, OS-assigned
        // port.
        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

        // Dial the peer identified by the multi-address given as the second
        // command-line argument, if any.
        if let Some(addr) = std::env::args().nth(1) {
            let remote: Multiaddr = addr.parse()?;
            swarm.dial(remote)?;
            println!("Dialed {addr}")
        }

        // Start the event loop to drive the swarm.
        loop {
            match swarm.select_next_some().await {
                SwarmEvent::NewListenAddr { address, .. } => println!("Listening on {address:?}"),
                SwarmEvent::Behaviour(event) => println!("{event:?}"),
                _ => {}
            }
        }
    }
}