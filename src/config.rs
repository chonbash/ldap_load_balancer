use serde::{Deserialize, Serialize};
use std::path::Path;
use std::fs;
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub listen: ListenConfig,
    pub backend: BackendConfig,
    pub tls: Option<TlsConfig>,
    pub io_threads: Option<u32>,
    pub proxyauthz: Option<bool>,
    /// Optional HTTP listen address for metrics and health (e.g. "0.0.0.0:9090"). Endpoints: GET /metrics (Prometheus), GET /health (liveness), GET /ready (readiness).
    pub metrics_listen: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenConfig {
    pub url: String,
}

/// Strategy for selecting a backend server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BalanceStrategy {
    #[default]
    Random,
    RoundRobin,
    RingHash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    pub bind: BindConfig,
    pub servers: Vec<BackendServer>,
    /// Load balance strategy: random, round_robin, ring_hash.
    #[serde(default)]
    pub strategy: BalanceStrategy,
    /// Number of virtual nodes per server for ring_hash (default 100).
    pub ring_hash_vnodes: Option<u32>,
    /// Health check interval in seconds (default 10). Set to 0 to disable (backend_up metric will show -1 = unknown).
    pub health_check_interval_sec: Option<u64>,
    /// Health check timeout in seconds (default 3).
    pub health_check_timeout_sec: Option<u64>,
    /// Health check type: whoami (default), bind (simple bind with backend credentials), tcp (connect only).
    pub health_check: Option<String>,
    /// Число попыток подключения к backend при proxy (default 3). При каждой попытке вызывается выбор узла заново (для random/round_robin — другой узел).
    pub connect_attempts: Option<u32>,
    /// Задержка между попытками подключения в миллисекундах (default 50).
    pub connect_retry_delay_ms: Option<u64>,
    /// Для ldaps:// бэкендов: не проверять сертификат сервера (только для тестов/внутренней сети).
    pub tls_skip_verify: Option<bool>,
    /// При конфиге из etcd: ключ с PEM CA или бандла для проверки сертификатов ldaps:// бэкендов.
    pub tls_ca_etcd_key: Option<String>,
    /// When true, write operations (Add/Modify/Delete/ModifyDN) after Bind use the same backend as the Bind (sticky session). In proxy mode one backend stream per connection already provides this; option is for explicit configuration and documentation. Default true.
    pub sticky_writes: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindConfig {
    pub method: String,
    pub binddn: Option<String>,
    pub credentials: Option<String>,
    pub network_timeout: Option<u64>,
    pub tls_cacert: Option<String>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendServer {
    pub uri: String,
    pub starttls: Option<String>,
    pub retry: Option<u64>,
    pub max_pending_ops: Option<u32>,
    pub conn_max_pending: Option<u32>,
    pub numconns: Option<u32>,
    pub bindconns: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub ca_file: Option<String>,
    /// When config is from etcd: key containing PEM certificate (alternative to cert_file).
    pub cert_etcd_key: Option<String>,
    /// When config is from etcd: key containing PEM private key (alternative to key_file).
    pub key_etcd_key: Option<String>,
    /// When config is from etcd: key containing PEM CA certificate (optional).
    pub ca_etcd_key: Option<String>,
    pub share_slapd_ctx: Option<bool>,
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    pub fn from_str(content: &str) -> Result<Self> {
        let config: Config = serde_yaml::from_str(content)?;
        Ok(config)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: ListenConfig {
                url: "ldap://127.0.0.1:1389".to_string(),
            },
            backend: BackendConfig {
                bind: BindConfig {
                    method: "simple".to_string(),
                    binddn: None,
                    credentials: None,
                    network_timeout: Some(5),
                    tls_cacert: None,
                    tls_cert: None,
                    tls_key: None,
                },
                servers: vec![],
                strategy: BalanceStrategy::default(),
                ring_hash_vnodes: None,
                health_check_interval_sec: Some(10),
                health_check_timeout_sec: Some(3),
                health_check: Some("whoami".to_string()),
                connect_attempts: None,
            connect_retry_delay_ms: None,
            tls_skip_verify: None,
            tls_ca_etcd_key: None,
            sticky_writes: Some(true),
        },
            tls: None,
            io_threads: Some(1),
            proxyauthz: Some(false),
            metrics_listen: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.listen.url, "ldap://127.0.0.1:1389");
        assert_eq!(config.backend.servers.len(), 0);
        assert_eq!(config.backend.bind.method, "simple");
        assert_eq!(config.io_threads, Some(1));
        assert_eq!(config.proxyauthz, Some(false));
    }

    #[test]
    fn test_config_from_str() {
        let yaml = r#"
listen:
  url: "ldap://0.0.0.0:389"
backend:
  bind:
    method: "simple"
    binddn: "cn=admin,dc=example,dc=com"
    credentials: "password"
    network_timeout: 10
  servers:
    - uri: "ldap://ldap1.example.com:389"
      numconns: 20
      bindconns: 10
    - uri: "ldap://ldap2.example.com:389"
      numconns: 15
tls:
  cert_file: "/path/to/cert.pem"
  key_file: "/path/to/key.pem"
io_threads: 4
proxyauthz: true
"#;
        let config = Config::from_str(yaml).unwrap();
        assert_eq!(config.listen.url, "ldap://0.0.0.0:389");
        assert_eq!(config.backend.servers.len(), 2);
        assert_eq!(config.backend.servers[0].uri, "ldap://ldap1.example.com:389");
        assert_eq!(config.backend.servers[0].numconns, Some(20));
        assert_eq!(config.backend.servers[0].bindconns, Some(10));
        assert_eq!(config.backend.servers[1].uri, "ldap://ldap2.example.com:389");
        assert_eq!(config.backend.servers[1].numconns, Some(15));
        assert_eq!(config.backend.bind.binddn, Some("cn=admin,dc=example,dc=com".to_string()));
        assert_eq!(config.backend.bind.credentials, Some("password".to_string()));
        assert_eq!(config.backend.bind.network_timeout, Some(10));
        assert_eq!(config.tls.as_ref().unwrap().cert_file, Some("/path/to/cert.pem".to_string()));
        assert_eq!(config.io_threads, Some(4));
        assert_eq!(config.proxyauthz, Some(true));
        assert_eq!(config.backend.strategy, BalanceStrategy::Random);
    }

    #[test]
    fn test_config_from_str_ring_hash() {
        let yaml = r#"
listen:
  url: "ldap://:1389"
backend:
  strategy: ring_hash
  ring_hash_vnodes: 200
  bind:
    method: "simple"
  servers:
    - uri: "ldap://ldap1:389"
    - uri: "ldap://ldap2:389"
"#;
        let config = Config::from_str(yaml).unwrap();
        assert_eq!(config.backend.strategy, BalanceStrategy::RingHash);
        assert_eq!(config.backend.ring_hash_vnodes, Some(200));
    }

    #[test]
    fn test_config_from_str_minimal() {
        let yaml = r#"
listen:
  url: "ldap://:1389"
backend:
  bind:
    method: "simple"
  servers:
    - uri: "ldap://localhost:389"
"#;
        let config = Config::from_str(yaml).unwrap();
        assert_eq!(config.listen.url, "ldap://:1389");
        assert_eq!(config.backend.servers.len(), 1);
        assert_eq!(config.backend.servers[0].uri, "ldap://localhost:389");
        assert_eq!(config.backend.servers[0].numconns, None);
    }

    #[test]
    fn test_config_from_file() {
        let yaml = r#"
listen:
  url: "ldap://127.0.0.1:1389"
backend:
  bind:
    method: "simple"
  servers:
    - uri: "ldap://localhost:389"
      retry: 5000
      max_pending_ops: 100
"#;
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(yaml.as_bytes()).unwrap();
        file.flush().unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert_eq!(config.listen.url, "ldap://127.0.0.1:1389");
        assert_eq!(config.backend.servers.len(), 1);
        assert_eq!(config.backend.servers[0].uri, "ldap://localhost:389");
        assert_eq!(config.backend.servers[0].retry, Some(5000));
        assert_eq!(config.backend.servers[0].max_pending_ops, Some(100));
    }

    #[test]
    fn test_config_from_str_invalid_yaml() {
        let yaml = "invalid: yaml: content: [";
        assert!(Config::from_str(yaml).is_err());
    }

    #[test]
    fn test_config_from_file_nonexistent() {
        assert!(Config::from_file("/nonexistent/path/config.yaml").is_err());
    }

    #[test]
    fn test_config_with_optional_fields() {
        let yaml = r#"
listen:
  url: "ldaps://0.0.0.0:636"
backend:
  bind:
    method: "simple"
    tls_cacert: "/path/to/ca.pem"
    tls_cert: "/path/to/cert.pem"
    tls_key: "/path/to/key.pem"
  servers:
    - uri: "ldaps://ldap.example.com:636"
      starttls: "demand"
      conn_max_pending: 5
      bindconns: 3
tls:
  cert_file: "/etc/ssl/cert.pem"
  key_file: "/etc/ssl/key.pem"
  ca_file: "/etc/ssl/ca.pem"
  share_slapd_ctx: true
"#;
        let config = Config::from_str(yaml).unwrap();
        assert_eq!(config.listen.url, "ldaps://0.0.0.0:636");
        assert_eq!(config.backend.bind.tls_cacert, Some("/path/to/ca.pem".to_string()));
        assert_eq!(config.backend.servers[0].starttls, Some("demand".to_string()));
        assert_eq!(config.backend.servers[0].conn_max_pending, Some(5));
        assert_eq!(config.backend.servers[0].bindconns, Some(3));
        assert_eq!(config.tls.as_ref().unwrap().share_slapd_ctx, Some(true));
    }
}
