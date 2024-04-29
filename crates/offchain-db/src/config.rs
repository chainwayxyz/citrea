use serde::Deserialize;

/// Offchain DB Config
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct OffchainDbConfig {
    db_host: String,
    db_port: usize,
    db_user: String,
    db_password: String,
    db_name: String,
}

impl OffchainDbConfig {
    pub fn new(
        db_host: String,
        db_port: usize,
        db_user: String,
        db_password: String,
        db_name: String,
    ) -> Self {
        Self {
            db_host,
            db_port,
            db_user,
            db_password,
            db_name,
        }
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

impl Default for OffchainDbConfig {
    fn default() -> Self {
        Self {
            db_host: "localhost".to_string(),
            db_port: 5432,
            db_user: "postgres".to_string(),
            db_password: "postgres".to_string(),
            db_name: "postgres".to_string(),
        }
    }
}
