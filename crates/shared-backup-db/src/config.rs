use deadpool_postgres::tokio_postgres::Config;
use serde::Deserialize;

/// Offchain DB Config
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct SharedBackupDbConfig {
    db_host: String,
    db_port: usize,
    db_user: String,
    db_password: String,
    db_name: String,
    max_pool_size: Option<usize>,
}

impl SharedBackupDbConfig {
    pub fn new(
        db_host: String,
        db_port: usize,
        db_user: String,
        db_password: String,
        db_name: String,
        max_pool_size: Option<usize>,
    ) -> Self {
        Self {
            db_host,
            db_port,
            db_user,
            db_password,
            db_name,
            max_pool_size,
        }
    }

    pub fn db_host(&self) -> &String {
        &self.db_host
    }

    pub fn db_port(&self) -> usize {
        self.db_port
    }

    pub fn db_user(&self) -> &String {
        &self.db_user
    }

    pub fn db_password(&self) -> &String {
        &self.db_password
    }

    pub fn db_name(&self) -> &String {
        &self.db_name
    }

    pub fn max_pool_size(&self) -> Option<usize> {
        self.max_pool_size
    }

    pub fn set_db_name(mut self, db_name: String) -> Self {
        self.db_name = db_name;
        self
    }

    pub fn parse_to_connection_string(&self) -> String {
        format!(
            "host={} port={} user={} password={} dbname={}",
            self.db_host, self.db_port, self.db_user, self.db_password, self.db_name
        )
    }

    pub fn parse_to_connection_string_with_db(&self, db_name: String) -> String {
        format!(
            "host={} port={} user={} password={} dbname={}",
            self.db_host, self.db_port, self.db_user, self.db_password, db_name
        )
    }
}

impl Default for SharedBackupDbConfig {
    fn default() -> Self {
        Self {
            db_host: "localhost".to_string(),
            db_port: 5432,
            db_user: "postgres".to_string(),
            db_password: "postgres".to_string(),
            db_name: "postgres".to_string(),
            max_pool_size: None,
        }
    }
}

impl From<SharedBackupDbConfig> for Config {
    fn from(val: SharedBackupDbConfig) -> Self {
        let mut cfg = Config::new();
        cfg.host(val.db_host())
            .port(val.db_port() as u16)
            .user(val.db_user())
            .password(val.db_password())
            .dbname(val.db_name())
            .clone()
    }
}
