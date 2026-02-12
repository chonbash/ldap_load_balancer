//! Управление конфигурацией: загрузка из файла или etcd с обновлением "на лету".

use crate::backend::BackendPool;
use crate::config::{BackendConfig, BackendServer, BindConfig, Config};
use crate::tls;
use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use etcd_client::{Client, EventType};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

/// Минимальный backend с одним заглушечным сервером для начальной инициализации ArcSwap.
fn dummy_backend_config() -> BackendConfig {
    BackendConfig {
        bind: BindConfig {
            method: "simple".to_string(),
            binddn: None,
            credentials: None,
            network_timeout: Some(5),
            tls_cacert: None,
            tls_cert: None,
            tls_key: None,
        },
        strategy: crate::config::BalanceStrategy::default(),
        ring_hash_vnodes: None,
        health_check_interval_sec: Some(0),
        health_check_timeout_sec: Some(3),
        connect_attempts: None,
        connect_retry_delay_ms: None,
        tls_skip_verify: None,
        tls_ca_etcd_key: None,
        servers: vec![BackendServer {
            uri: "ldap://127.0.0.1:1".to_string(),
            starttls: None,
            retry: None,
            max_pending_ops: None,
            conn_max_pending: None,
            numconns: Some(1),
            bindconns: Some(0),
        }],
    }
}

/// Хранилище живой конфигурации: конфиг и пул бэкендов обновляются без перезапуска.
#[derive(Clone)]
pub struct LiveConfig {
    /// Текущая конфигурация (обновляется при изменении в etcd).
    config: Arc<ArcSwap<Config>>,
    /// Текущий пул бэкендов (пересоздаётся при изменении секции backend).
    backend_pool: Arc<ArcSwap<BackendPool>>,
}

impl LiveConfig {
    /// Создаёт живой конфиг из уже загруженного `Config` (без etcd/watch).
    /// Удобно для тестов и для режима "только файл" без динамического обновления.
    pub fn from_config(cfg: Config) -> Result<Self> {
        let config = Arc::new(ArcSwap::from_pointee(Config::default()));
        let backend_pool: Arc<ArcSwap<BackendPool>> = Arc::new(ArcSwap::from_pointee(
            BackendPool::new(dummy_backend_config(), None).context("Initial dummy backend")?,
        ));
        let new_pool = apply_config(&cfg, &config, &backend_pool, None)?;
        spawn_health_task(new_pool, Arc::clone(&backend_pool));
        Ok(LiveConfig {
            config,
            backend_pool,
        })
    }

    /// Текущий конфиг (снимок на момент вызова).
    pub fn config(&self) -> arc_swap::Guard<Arc<Config>> {
        self.config.load()
    }

    /// Текущий пул бэкендов (снимок на момент вызова).
    pub fn backend_pool(&self) -> Arc<BackendPool> {
        Arc::clone(&*self.backend_pool.load())
    }

    /// Количество серверов в текущем пуле (для логов).
    pub fn server_count(&self) -> usize {
        (*self.backend_pool.load()).server_count()
    }

    /// Включён ли proxyauthz по текущей конфигурации.
    pub fn proxyauthz(&self) -> bool {
        self.config.load().proxyauthz.unwrap_or(false)
    }
}

/// Источник конфигурации: из файла (однократно) или из etcd (с watch).
pub enum ConfigSource {
    File {
        path: PathBuf,
    },
    Etcd {
        endpoints: Vec<String>,
        config_key: String,
        /// Файл для начальной загрузки, если ключ в etcd пуст или отсутствует.
        fallback_file: Option<PathBuf>,
    },
}

impl ConfigSource {
    /// Загружает начальную конфигурацию и при необходимости запускает фоновое обновление.
    /// Для etcd порождает задачу, которая следит за ключом и обновляет конфиг/пул.
    pub async fn load(self) -> Result<LiveConfig> {
        let config = Arc::new(ArcSwap::from_pointee(Config::default()));
        let backend_pool: Arc<ArcSwap<BackendPool>> = Arc::new(ArcSwap::from_pointee(
            BackendPool::new(dummy_backend_config(), None).context("Initial dummy backend")?,
        ));

        match self {
            ConfigSource::File { path } => {
                let cfg = Config::from_file(&path).context("Load config from file")?;
                let new_pool = apply_config(&cfg, &config, &backend_pool, None)?;
                spawn_health_task(new_pool, Arc::clone(&backend_pool));
                info!("Configuration loaded from file: {:?}", path);
            }
            ConfigSource::Etcd {
                endpoints,
                config_key,
                fallback_file,
            } => {
                if std::path::Path::new("/.dockerenv").exists() {
                    info!("Running in Docker: waiting 3s for DNS before connecting to etcd");
                    tokio::time::sleep(Duration::from_secs(3)).await;
                }
                let mut client = Client::connect(endpoints.clone(), None)
                    .await
                    .context("Connect to etcd")?;

                let initial_yaml = match client.get(config_key.as_str(), None).await {
                    Ok(resp) => resp
                        .kvs()
                        .first()
                        .and_then(|kv| kv.value_str().ok())
                        .map(String::from),
                    Err(e) => {
                        warn!("etcd get failed: {}; using fallback", e);
                        None
                    }
                };

                let initial_yaml = initial_yaml.or_else(|| {
                    fallback_file.as_ref().and_then(|p| {
                        std::fs::read_to_string(p)
                            .map_err(|e| {
                                warn!("Fallback file read failed: {}", e);
                            })
                            .ok()
                    })
                });

                let initial_yaml = initial_yaml.context(
                    "No config in etcd and no fallback file (or fallback read failed)",
                )?;

                let cfg = Config::from_str(&initial_yaml).context("Parse initial config YAML")?;
                let backend_ca_pem = fetch_backend_ca_from_etcd(&mut client, &cfg).await;
                let new_pool = apply_config(&cfg, &config, &backend_pool, backend_ca_pem)?;
                spawn_health_task(new_pool, Arc::clone(&backend_pool));
                info!(
                    "Initial configuration loaded from etcd key: {}",
                    config_key
                );

                // Фоновая задача: watch ключа и обновление конфига/пула
                let config_key_watch = config_key.clone();
                let config_swap = Arc::clone(&config);
                let pool_swap = Arc::clone(&backend_pool);
                tokio::spawn(async move {
                    if let Err(e) = run_etcd_watch(
                        endpoints,
                        config_key_watch,
                        config_swap,
                        pool_swap,
                    )
                    .await
                    {
                        error!("etcd watch task failed: {}", e);
                    }
                });
            }
        }

        Ok(LiveConfig {
            config,
            backend_pool,
        })
    }
}

/// Загружает из etcd PEM CA/бандл по ключу `backend.tls_ca_etcd_key`, если задан.
async fn fetch_backend_ca_from_etcd(client: &mut Client, cfg: &Config) -> Option<Vec<u8>> {
    let key = cfg.backend.tls_ca_etcd_key.as_ref()?;
    let resp = client.get(key.as_str(), None).await.ok()?;
    let kv = resp.kvs().first()?;
    Some(kv.value().to_vec())
}

/// Применяет конфиг: обновляет ArcSwap конфига и при изменении backend — пересоздаёт пул.
/// Возвращает новый пул, чтобы вызывающий код мог запустить для него задачу health check.
/// Для конфига из etcd передайте backend_ca_pem из fetch_backend_ca_from_etcd.
fn apply_config(
    cfg: &Config,
    config: &Arc<ArcSwap<Config>>,
    backend_pool: &Arc<ArcSwap<BackendPool>>,
    backend_ca_pem: Option<Vec<u8>>,
) -> Result<Arc<BackendPool>> {
    if cfg.backend.servers.is_empty() {
        anyhow::bail!("No backend servers in config");
    }
    config.store(Arc::new(cfg.clone()));
    let pool = BackendPool::new(cfg.backend.clone(), backend_ca_pem).context("Build backend pool")?;
    let pool_arc = Arc::new(pool);
    backend_pool.store(Arc::clone(&pool_arc));
    Ok(pool_arc)
}

/// Запускает фоновую задачу health check для данного пула. Задача завершается, когда пул заменён в ArcSwap.
fn spawn_health_task(
    pool: Arc<BackendPool>,
    backend_pool: Arc<ArcSwap<BackendPool>>,
) {
    let interval_sec = pool.health_interval_sec();
    if interval_sec == 0 {
        return;
    }
    tokio::spawn(async move {
        let interval = Duration::from_secs(interval_sec);
        loop {
            let current = backend_pool.load();
            if !Arc::ptr_eq(&*current, &pool) {
                break;
            }
            pool.run_health_checks().await;
            tokio::time::sleep(interval).await;
        }
    });
}

/// Цикл watch за ключом etcd с переподключением при обрыве.
async fn run_etcd_watch(
    endpoints: Vec<String>,
    config_key: String,
    config: Arc<ArcSwap<Config>>,
    backend_pool: Arc<ArcSwap<BackendPool>>,
) -> Result<()> {
    let mut backoff = Duration::from_secs(1);
    const MAX_BACKOFF: Duration = Duration::from_secs(60);

    loop {
        match watch_loop(
            endpoints.clone(),
            config_key.clone(),
            Arc::clone(&config),
            Arc::clone(&backend_pool),
        )
        .await
        {
            Ok(()) => {}
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("dns error") || msg.contains("Name or service not known") {
                    error!(
                        "etcd watch error: {}; reconnecting in {:?}. \
                         If running outside Docker, set ETCD_ENDPOINTS=http://127.0.0.1:12379 (or your etcd host:port)",
                        e, backoff
                    );
                } else {
                    error!("etcd watch error: {}; reconnecting in {:?}", e, backoff);
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}

async fn watch_loop(
    endpoints: Vec<String>,
    config_key: String,
    config: Arc<ArcSwap<Config>>,
    backend_pool: Arc<ArcSwap<BackendPool>>,
) -> Result<()> {
    let mut client = Client::connect(endpoints, None).await?;
    let mut stream = client.watch(config_key.as_str(), None).await?;

    while let Some(resp) = stream.message().await? {
        for event in resp.events() {
            if event.event_type() != EventType::Put {
                continue;
            }
            let kv = match event.kv() {
                Some(k) => k,
                None => continue,
            };
            let value = match kv.value_str() {
                Ok(s) => s.to_string(),
                Err(_) => continue,
            };
            match Config::from_str(&value) {
                Ok(cfg) => {
                    let backend_ca_pem = fetch_backend_ca_from_etcd(&mut client, &cfg).await;
                    match apply_config(&cfg, &config, &backend_pool, backend_ca_pem) {
                        Ok(new_pool) => {
                            spawn_health_task(new_pool, Arc::clone(&backend_pool));
                            info!("Configuration updated from etcd (live reload)");
                        }
                        Err(e) => error!("Apply config from etcd failed: {}", e),
                    }
                }
                Err(e) => {
                    error!("Invalid YAML from etcd: {}", e);
                }
            }
        }
    }
    Ok(())
}

/// Spawns a background task that watches etcd TLS keys and updates the given TlsAcceptor swap on change.
/// Call this when using LDAPS with cert_etcd_key/key_etcd_key so new connections use updated certs.
pub fn spawn_etcd_tls_watch(
    endpoints: Vec<String>,
    cert_key: String,
    key_key: String,
    ca_key: Option<String>,
    tls_swap: Arc<ArcSwap<TlsAcceptor>>,
) {
    tokio::spawn(async move {
        let mut backoff = Duration::from_secs(1);
        const MAX_BACKOFF: Duration = Duration::from_secs(60);
        loop {
            match run_etcd_tls_watch_loop(
                endpoints.clone(),
                cert_key.clone(),
                key_key.clone(),
                ca_key.clone(),
                Arc::clone(&tls_swap),
            )
            .await
            {
                Ok(()) => {}
                Err(e) => {
                    error!("etcd TLS watch error: {}; reconnecting in {:?}", e, backoff);
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
        }
    });
}

async fn run_etcd_tls_watch_loop(
    endpoints: Vec<String>,
    cert_key: String,
    key_key: String,
    ca_key: Option<String>,
    tls_swap: Arc<ArcSwap<TlsAcceptor>>,
) -> Result<()> {
    let mut client = Client::connect(endpoints, None).await?;
    let mut stream = client.watch(cert_key.as_str(), None).await?;
    while let Some(resp) = stream.message().await? {
        for event in resp.events() {
            if event.event_type() != EventType::Put {
                continue;
            }
            match reload_tls_from_etcd(&mut client, &cert_key, &key_key, ca_key.as_deref()).await {
                Ok(new_config) => {
                    tls_swap.store(Arc::new(TlsAcceptor::from(new_config)));
                    info!("TLS certificates reloaded from etcd");
                }
                Err(e) => {
                    error!("Failed to reload TLS from etcd: {}", e);
                }
            }
            break;
        }
    }
    Ok(())
}

async fn reload_tls_from_etcd(
    client: &mut Client,
    cert_key: &str,
    key_key: &str,
    ca_key: Option<&str>,
) -> Result<Arc<rustls::ServerConfig>> {
    tls::load_server_config_from_etcd(client, cert_key, key_key, ca_key).await
}
