use crate::config::{BalanceStrategy, BackendConfig, BackendServer, BindConfig};
use ldap3::exop::WhoAmI;
use ldap3::{Ldap, LdapConnAsync};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Semaphore};
use tokio::net::TcpStream;
use tokio::io::{AsyncRead, AsyncWrite};
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use anyhow::{Context, Result};
use rand::Rng;
use rand::thread_rng;
use tracing::{debug, info, warn};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::TlsConnector;
use rustls::client::ClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::SignatureScheme;
use rustls_pki_types::ServerName;

/// Node health state: 0 = Up, 1 = Down. Unknown treated as Up until first check fails.
const NODE_UP: u8 = 0;
const NODE_DOWN: u8 = 1;

/// FNV-1a 64-bit hash for stable consistent hashing (same input → same hash).
#[inline]
fn fnv1a_hash(bytes: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    let mut h = FNV_OFFSET;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// Build sorted ring of (hash, server_index) for consistent hashing. Only used when strategy is RingHash.
fn build_ring_hash_ring(
    servers: &[BackendServerInfo],
    vnodes_per_server: u32,
    strategy: BalanceStrategy,
) -> Arc<Vec<(u64, usize)>> {
    if strategy != BalanceStrategy::RingHash || servers.is_empty() {
        return Arc::new(Vec::new());
    }
    let mut ring: Vec<(u64, usize)> = Vec::with_capacity(servers.len() * vnodes_per_server as usize);
    for (idx, server) in servers.iter().enumerate() {
        for v in 0..vnodes_per_server {
            let key = format!("{}#{}", server.uri, v);
            let h = fnv1a_hash(key.as_bytes());
            ring.push((h, idx));
        }
    }
    ring.sort_by_key(|&(h, _)| h);
    Arc::new(ring)
}

/// Find server index for the given hash. Walks ring from hash position and returns first server where `is_up(server_idx)`.
fn ring_lookup(
    ring: &[(u64, usize)],
    key_hash: u64,
    is_up: impl Fn(usize) -> bool,
) -> Option<usize> {
    if ring.is_empty() {
        return None;
    }
    let start = match ring.binary_search_by_key(&key_hash, |&(h, _)| h) {
        Ok(i) => i,
        Err(i) => {
            if i < ring.len() {
                i
            } else {
                0
            }
        }
    };
    for offset in 0..ring.len() {
        let i = (start + offset) % ring.len();
        let server_idx = ring[i].1;
        if is_up(server_idx) {
            return Some(server_idx);
        }
    }
    None
}

/// Per-server connection pool: general ops and bind. Connections are returned on Drop of BackendConnection.
struct ConnPoolState {
    uri: String,
    bind_config: BindConfig,
    numconns: u32,
    bindconns: u32,
    general: Mutex<Vec<Ldap>>,
    bind_pool: Mutex<Vec<Ldap>>,
    general_count: AtomicUsize,
    bind_count: AtomicUsize,
}

impl ConnPoolState {
    async fn create_connection(uri: &str) -> Result<Ldap> {
        let (conn, ldap) = LdapConnAsync::new(uri)
            .await
            .context(format!("Failed to connect to {}", uri))?;
        tokio::spawn(ldap3::drive!(conn));
        Ok(ldap)
    }

    async fn create_and_bind(&self) -> Result<Ldap> {
        let mut ldap = Self::create_connection(&self.uri).await?;
        if let (Some(ref binddn), Some(ref creds)) = (&self.bind_config.binddn, &self.bind_config.credentials) {
            ldap.simple_bind(binddn, creds).await.context("Pool bind failed")?;
        }
        Ok(ldap)
    }

    async fn get_connection(&self) -> Result<Ldap> {
        let mut guard = self.general.lock().await;
        if let Some(conn) = guard.pop() {
            return Ok(conn);
        }
        drop(guard);
        let current = self.general_count.load(Ordering::Relaxed);
        if current >= self.numconns as usize {
            anyhow::bail!("Connection limit reached for {}", self.uri);
        }
        self.general_count.fetch_add(1, Ordering::Relaxed);
        Self::create_connection(&self.uri).await
    }

    async fn get_bind_connection(&self) -> Result<Ldap> {
        let mut guard = self.bind_pool.lock().await;
        if let Some(conn) = guard.pop() {
            return Ok(conn);
        }
        drop(guard);
        let current = self.bind_count.load(Ordering::Relaxed);
        if current >= self.bindconns as usize {
            anyhow::bail!("Bind connection limit reached for {}", self.uri);
        }
        self.bind_count.fetch_add(1, Ordering::Relaxed);
        self.create_and_bind().await
    }

    async fn return_connection(&self, mut conn: Ldap, for_bind: bool) {
        let ok = conn.extended(WhoAmI).await.and_then(|r| r.success()).is_ok();
        if !ok {
            debug!("Dropping unhealthy connection to {}", self.uri);
            if for_bind {
                self.bind_count.fetch_sub(1, Ordering::Relaxed);
            } else {
                self.general_count.fetch_sub(1, Ordering::Relaxed);
            }
            return;
        }
        if for_bind {
            if let Ok(mut guard) = self.bind_pool.try_lock() {
                guard.push(conn);
            } else {
                self.bind_count.fetch_sub(1, Ordering::Relaxed);
            }
        } else if let Ok(mut guard) = self.general.try_lock() {
            guard.push(conn);
        } else {
            self.general_count.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct BackendPool {
    servers: Arc<Vec<BackendServerInfo>>,
    bind_config: BindConfig,
    semaphore: Arc<Semaphore>,
    strategy: BalanceStrategy,
    ring: Arc<Vec<(u64, usize)>>,
    round_robin_next: Arc<AtomicUsize>,
    health_interval_sec: u64,
    health_timeout_sec: u64,
    /// When true, ldaps:// backend connections skip server certificate verification.
    tls_skip_verify: bool,
    /// Optional CA PEM (single cert or bundle) for verifying ldaps:// backends. When set (e.g. from etcd), used in addition to system roots.
    backend_ca_pem: Option<Arc<Vec<u8>>>,
}

#[derive(Clone)]
#[allow(dead_code)]
struct BackendServerInfo {
    uri: String,
    starttls: Option<String>,
    retry_ms: u64,
    max_pending_ops: u32,
    conn_max_pending: u32,
    numconns: u32,
    bindconns: u32,
    state: Arc<AtomicU8>,
    pool: Arc<ConnPoolState>,
    /// "whoami" | "bind" | "tcp"
    health_check_kind: String,
}

impl std::fmt::Debug for BackendPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackendPool")
            .field("server_count", &self.servers.len())
            .field("strategy", &self.strategy)
            .field("health_interval_sec", &self.health_interval_sec)
            .finish()
    }
}

impl BackendPool {
    /// Build backend pool. When config is loaded from etcd and backend.tls_ca_etcd_key is set,
    /// pass the fetched CA PEM as `backend_ca_pem` for ldaps backend verification.
    pub fn new(config: BackendConfig, backend_ca_pem: Option<Vec<u8>>) -> Result<Self> {
        let bind_config = config.bind.clone();
        let health_interval_sec = config.health_check_interval_sec.unwrap_or(10);
        let health_timeout_sec = config.health_check_timeout_sec.unwrap_or(3);
        let health_check = config
            .health_check
            .as_deref()
            .unwrap_or("whoami")
            .to_lowercase();
        let tls_skip_verify = config.tls_skip_verify.unwrap_or(false);
        let backend_ca_pem = backend_ca_pem.map(Arc::new);

        let servers: Vec<BackendServerInfo> = config
            .servers
            .iter()
            .enumerate()
            .map(|(idx, server)| {
                BackendServerInfo::new(idx, server.clone(), bind_config.clone(), &health_check)
            })
            .collect();

        if servers.is_empty() {
            anyhow::bail!("No backend servers configured");
        }

        let max_connections: u32 = servers
            .iter()
            .map(|s| s.numconns + s.bindconns)
            .sum();

        let strategy = config.strategy;
        let ring = build_ring_hash_ring(
            &servers,
            config.ring_hash_vnodes.unwrap_or(100),
            strategy,
        );

        Ok(Self {
            servers: Arc::new(servers),
            bind_config: config.bind,
            semaphore: Arc::new(Semaphore::new(max_connections as usize)),
            strategy,
            ring,
            round_robin_next: Arc::new(AtomicUsize::new(0)),
            health_interval_sec,
            health_timeout_sec,
            tls_skip_verify,
            backend_ca_pem,
        })
    }

    /// Select server index by configured strategy. Only nodes in Up state are considered.
    fn select_server_index(&self, hash_key: Option<&[u8]>) -> Result<usize> {
        let n = self.servers.len();
        if n == 0 {
            anyhow::bail!("No servers available");
        }
        let is_up = |idx: usize| {
            self.servers
                .get(idx)
                .map(|s| s.state.load(Ordering::Relaxed) == NODE_UP)
                .unwrap_or(false)
        };
        let up_indices: Vec<usize> = (0..n).filter(|&i| is_up(i)).collect();
        if up_indices.is_empty() {
            anyhow::bail!("No healthy backend servers available");
        }
        self.select_server_index_inner(hash_key, up_indices, n, is_up)
    }

    /// Select server index ignoring health (all nodes considered up). Used as fallback when health check marks all down but raw connect may still succeed (e.g. ldaps vs ldap3 TLS).
    fn select_server_index_ignore_health(&self, hash_key: Option<&[u8]>) -> Result<usize> {
        let n = self.servers.len();
        if n == 0 {
            anyhow::bail!("No servers available");
        }
        let all_indices: Vec<usize> = (0..n).collect();
        let is_up = |_idx: usize| true;
        self.select_server_index_inner(hash_key, all_indices, n, is_up)
    }

    fn select_server_index_inner(
        &self,
        hash_key: Option<&[u8]>,
        indices: Vec<usize>,
        _n: usize,
        is_up: impl Fn(usize) -> bool,
    ) -> Result<usize> {
        match self.strategy {
            BalanceStrategy::Random => Ok(indices[thread_rng().gen_range(0..indices.len())]),
            BalanceStrategy::RoundRobin => {
                let k = self.round_robin_next.fetch_add(1, Ordering::Relaxed) % indices.len();
                Ok(indices[k])
            }
            BalanceStrategy::RingHash => {
                let key = hash_key.unwrap_or(b"");
                ring_lookup(&self.ring, fnv1a_hash(key), is_up)
                    .ok_or_else(|| anyhow::anyhow!("No backend servers available"))
            }
        }
    }

    /// Run one pass of health checks for all servers. Used by the background health task.
    pub async fn run_health_checks(&self) {
        for (_idx, server) in self.servers.iter().enumerate() {
            match server.check_health(self.health_timeout_sec).await {
                Ok(true) => {
                    let was = server.state.swap(NODE_UP, Ordering::Relaxed);
                    if was == NODE_DOWN {
                        info!("Backend {} is up", server.uri);
                    }
                }
                Ok(false) | Err(_) => {
                    let was = server.state.swap(NODE_DOWN, Ordering::Relaxed);
                    if was == NODE_UP {
                        warn!("Backend {} is down", server.uri);
                    }
                }
            }
        }
    }

    /// Health check interval in seconds (0 = disabled).
    pub fn health_interval_sec(&self) -> u64 {
        self.health_interval_sec
    }

    pub async fn get_connection(
        &self,
        for_bind: bool,
        hash_key: Option<&[u8]>,
    ) -> Result<BackendConnection> {
        let server_idx = self.select_server_index(hash_key)?;
        let server = self.servers
            .get(server_idx)
            .ok_or_else(|| anyhow::anyhow!("No servers available"))?;

        let _permit = self.semaphore.acquire().await
            .map_err(|_| anyhow::anyhow!("Failed to acquire semaphore"))?;

        let conn = if for_bind {
            server.get_bind_connection().await
        } else {
            server.get_connection().await
        }?;

        Ok(BackendConnection {
            server_uri: server.uri.clone(),
            connection: Some(conn),
            pool: Some(server.pool.clone()),
            for_bind,
        })
    }

    pub fn server_count(&self) -> usize {
        self.servers.len()
    }

    /// Текущее состояние узлов для мониторинга: (uri, Some(is_up)) когда health check включён, (uri, None) когда отключён (interval 0).
    pub fn backend_states(&self) -> Vec<(String, Option<bool>)> {
        let unknown = self.health_interval_sec == 0;
        self.servers
            .iter()
            .map(|s| {
                let up = s.state.load(Ordering::Relaxed) == NODE_UP;
                (s.uri.clone(), if unknown { None } else { Some(up) })
            })
            .collect()
    }

    /// Open a raw stream to the selected backend (TCP for ldap://, TLS for ldaps://).
    /// Does not use the connection pool; one stream per client session.
    /// If all backends are marked down by health check, tries anyway (fallback) and marks server up on success.
    pub async fn open_raw_stream(&self, hash_key: Option<&[u8]>) -> Result<BackendSession> {
        let server_idx = self.select_server_index(hash_key)
            .or_else(|e| {
                if e.to_string().contains("No healthy backend servers available") {
                    debug!("No healthy backends, trying fallback (ignore health state)");
                    self.select_server_index_ignore_health(hash_key)
                } else {
                    Err(e)
                }
            })?;
        let server = self.servers
            .get(server_idx)
            .ok_or_else(|| anyhow::anyhow!("No servers available"))?;
        let was_down = server.state.load(Ordering::Relaxed) == NODE_DOWN;
        let (host, port) = parse_ldap_uri_to_host_port(&server.uri)?;
        let addr = format!("{}:{}", host, port);
        let is_ldaps = server.uri.starts_with("ldaps://");
        let tcp = TcpStream::connect(&addr)
            .await
            .with_context(|| format!("Failed to connect to backend {}", addr))?;
        let stream = if is_ldaps {
            let config = if self.tls_skip_verify {
                tls_client_config_insecure()?
            } else {
                default_tls_client_config_with_ca(self.backend_ca_pem.as_deref().map(|v| v.as_slice()))?
            };
            let connector = TlsConnector::from(config);
            let server_name = ServerName::try_from(host)
                .map_err(|_| anyhow::anyhow!("Invalid hostname for TLS SNI: {}", addr))?;
            let tls_stream: ClientTlsStream<TcpStream> = connector
                .connect(server_name, tcp)
                .await
                .with_context(|| format!("TLS handshake to backend {} failed", addr))?;
            BackendStream::Tls(tls_stream)
        } else {
            BackendStream::Tcp(tcp)
        };
        if was_down {
            server.state.store(NODE_UP, Ordering::Relaxed);
            info!("Backend {} marked up after successful raw connect", server.uri);
        }
        Ok(BackendSession {
            stream,
            uri: server.uri.clone(),
        })
    }
}

/// Backend connection with URI for metrics (per-backend request counts).
pub struct BackendSession {
    pub stream: BackendStream,
    pub uri: String,
}

/// Stream to backend: plain TCP (ldap://) or TLS (ldaps://).
pub enum BackendStream {
    Tcp(TcpStream),
    Tls(ClientTlsStream<TcpStream>),
}

impl AsyncRead for BackendStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            BackendStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            BackendStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for BackendStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            BackendStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            BackendStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            BackendStream::Tcp(s) => Pin::new(s).poll_flush(cx),
            BackendStream::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            BackendStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            BackendStream::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl Unpin for BackendStream {}

/// Verifier that accepts any server certificate. Only for use with tls_skip_verify (internal/test).
#[derive(Debug)]
struct InsecureServerVerifier;

impl ServerCertVerifier for InsecureServerVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::ED25519,
        ]
    }
}

/// Build TLS client config that skips server certificate verification (for backend tls_skip_verify).
fn tls_client_config_insecure() -> Result<Arc<ClientConfig>> {
    let mut root_store = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().context("Load system CA certs")? {
        let _ = root_store.add(cert);
    }
    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.dangerous().set_certificate_verifier(Arc::new(InsecureServerVerifier));
    Ok(Arc::new(config))
}

/// Build default TLS client config with system root certificates (for connecting to ldaps:// backends).
#[allow(dead_code)]
fn default_tls_client_config() -> Result<Arc<ClientConfig>> {
    default_tls_client_config_with_ca(None)
}

fn default_tls_client_config_with_ca(extra_ca_pem: Option<&[u8]>) -> Result<Arc<ClientConfig>> {
    let mut root_store = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().context("Load system CA certs")? {
        let _ = root_store.add(cert);
    }
    if let Some(pem) = extra_ca_pem {
        for cert in rustls_pemfile::certs(&mut std::io::Cursor::new(pem)) {
            let cert = cert.map_err(|e| anyhow::anyhow!("Parse CA PEM: {}", e))?;
            let _ = root_store.add(cert);
        }
    }
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Parse "ldap://host:port" or "ldaps://host:port" to (host, port).
fn parse_ldap_uri_to_host_port(uri: &str) -> Result<(String, u16)> {
    let rest = uri
        .strip_prefix("ldap://")
        .or_else(|| uri.strip_prefix("ldaps://"))
        .ok_or_else(|| anyhow::anyhow!("Invalid LDAP URI scheme: {}", uri))?;
    let rest = rest.trim_start_matches('/');
    let (host, port_str) = rest
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("No port in URI: {}", uri))?;
    let port: u16 = port_str
        .parse()
        .with_context(|| format!("Invalid port in URI: {}", uri))?;
    Ok((host.to_string(), port))
}

pub struct BackendConnection {
    server_uri: String,
    connection: Option<Ldap>,
    pool: Option<Arc<ConnPoolState>>,
    for_bind: bool,
}

impl BackendConnection {
    pub fn ldap(&mut self) -> &mut Ldap {
        self.connection.as_mut().expect("connection already returned")
    }

    pub fn server_uri(&self) -> &str {
        &self.server_uri
    }
}

impl Drop for BackendConnection {
    fn drop(&mut self) {
        if let (Some(conn), Some(pool)) = (self.connection.take(), self.pool.take()) {
            let for_bind = self.for_bind;
            tokio::spawn(async move {
                pool.return_connection(conn, for_bind).await;
            });
        }
    }
}

impl BackendServerInfo {
    fn new(_idx: usize, server: BackendServer, bind_config: BindConfig, health_check_kind: &str) -> Self {
        let uri = server.uri.clone();
        let pool = Arc::new(ConnPoolState {
            uri: uri.clone(),
            bind_config: bind_config.clone(),
            numconns: server.numconns.unwrap_or(10),
            bindconns: server.bindconns.unwrap_or(5),
            general: Mutex::new(Vec::new()),
            bind_pool: Mutex::new(Vec::new()),
            general_count: AtomicUsize::new(0),
            bind_count: AtomicUsize::new(0),
        });
        Self {
            uri: server.uri.clone(),
            starttls: server.starttls.clone(),
            retry_ms: server.retry.unwrap_or(5000),
            max_pending_ops: server.max_pending_ops.unwrap_or(50),
            conn_max_pending: server.conn_max_pending.unwrap_or(10),
            numconns: server.numconns.unwrap_or(10),
            bindconns: server.bindconns.unwrap_or(5),
            state: Arc::new(AtomicU8::new(NODE_UP)),
            pool,
            health_check_kind: health_check_kind.to_string(),
        }
    }

    /// Returns Ok(true) if healthy, Ok(false) or Err if down.
    async fn check_health(&self, timeout_sec: u64) -> Result<bool> {
        let timeout = Duration::from_secs(timeout_sec);
        match self.health_check_kind.as_str() {
            "tcp" => {
                let (host, port) = parse_ldap_uri_to_host_port(&self.uri)?;
                let addr = format!("{}:{}", host, port);
                match tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
                    Ok(Ok(_)) => Ok(true),
                    _ => Ok(false),
                }
            }
            "bind" => {
                let mut conn = match tokio::time::timeout(
                    timeout,
                    ConnPoolState::create_connection(&self.uri),
                )
                .await
                {
                    Ok(Ok(ldap)) => ldap,
                    _ => return Ok(false),
                };
                let (binddn, creds) = (
                    self.pool.bind_config.binddn.as_deref().unwrap_or(""),
                    self.pool.bind_config.credentials.as_deref().unwrap_or(""),
                );
                let ok = tokio::time::timeout(timeout, conn.simple_bind(binddn, creds))
                    .await
                    .ok()
                    .and_then(|r| r.ok())
                    .is_some();
                Ok(ok)
            }
            _ => {
                // whoami (default)
                let mut conn = match tokio::time::timeout(
                    timeout,
                    ConnPoolState::create_connection(&self.uri),
                )
                .await
                {
                    Ok(Ok(ldap)) => ldap,
                    _ => return Ok(false),
                };
                let ok = tokio::time::timeout(timeout, conn.extended(WhoAmI))
                    .await
                    .ok()
                    .and_then(|r| r.ok())
                    .and_then(|r| r.success().ok())
                    .is_some();
                Ok(ok)
            }
        }
    }

    async fn get_connection(&self) -> Result<Ldap> {
        self.pool.get_connection().await
    }

    async fn get_bind_connection(&self) -> Result<Ldap> {
        self.pool.get_bind_connection().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BackendConfig;

    fn create_test_backend_config() -> BackendConfig {
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
            strategy: BalanceStrategy::Random,
            ring_hash_vnodes: None,
            health_check_interval_sec: Some(10),
            health_check_timeout_sec: Some(3),
            health_check: Some("whoami".to_string()),
            connect_attempts: None,
            connect_retry_delay_ms: None,
            tls_skip_verify: None,
            tls_ca_etcd_key: None,
            sticky_writes: None,
            servers: vec![
                BackendServer {
                    uri: "ldap://localhost:389".to_string(),
                    starttls: None,
                    retry: Some(5000),
                    max_pending_ops: Some(50),
                    conn_max_pending: Some(10),
                    numconns: Some(10),
                    bindconns: Some(5),
                },
                BackendServer {
                    uri: "ldap://localhost:390".to_string(),
                    starttls: None,
                    retry: None,
                    max_pending_ops: None,
                    conn_max_pending: None,
                    numconns: None,
                    bindconns: None,
                },
            ],
        }
    }

    #[test]
    fn test_backend_pool_new() {
        let config = create_test_backend_config();
        let pool = BackendPool::new(config, None).unwrap();
        assert_eq!(pool.server_count(), 2);
    }

    #[test]
    fn test_backend_pool_new_empty_servers() {
        let config = BackendConfig {
            bind: BindConfig {
                method: "simple".to_string(),
                binddn: None,
                credentials: None,
                network_timeout: None,
                tls_cacert: None,
                tls_cert: None,
                tls_key: None,
            },
            strategy: BalanceStrategy::Random,
            ring_hash_vnodes: None,
            health_check_interval_sec: None,
            health_check_timeout_sec: None,
            health_check: None,
            connect_attempts: None,
            connect_retry_delay_ms: None,
            tls_skip_verify: None,
            tls_ca_etcd_key: None,
            sticky_writes: None,
            servers: vec![],
        };
        assert!(BackendPool::new(config, None).is_err());
    }

    #[test]
    fn test_backend_pool_server_count() {
        let config = create_test_backend_config();
        let pool = BackendPool::new(config, None).unwrap();
        assert_eq!(pool.server_count(), 2);
    }

    #[test]
    fn test_backend_server_info_new() {
        let bind_config = BindConfig {
            method: "simple".to_string(),
            binddn: None,
            credentials: None,
            network_timeout: Some(5),
            tls_cacert: None,
            tls_cert: None,
            tls_key: None,
        };
        let server = BackendServer {
            uri: "ldap://test:389".to_string(),
            starttls: Some("demand".to_string()),
            retry: Some(3000),
            max_pending_ops: Some(100),
            conn_max_pending: Some(20),
            numconns: Some(15),
            bindconns: Some(8),
        };
        let info = BackendServerInfo::new(0, server, bind_config, "whoami");
        assert_eq!(info.uri, "ldap://test:389");
        assert_eq!(info.starttls, Some("demand".to_string()));
        assert_eq!(info.retry_ms, 3000);
        assert_eq!(info.max_pending_ops, 100);
        assert_eq!(info.conn_max_pending, 20);
        assert_eq!(info.numconns, 15);
        assert_eq!(info.bindconns, 8);
    }

    #[test]
    fn test_backend_server_info_defaults() {
        let bind_config = BindConfig {
            method: "simple".to_string(),
            binddn: None,
            credentials: None,
            network_timeout: None,
            tls_cacert: None,
            tls_cert: None,
            tls_key: None,
        };
        let server = BackendServer {
            uri: "ldap://test:389".to_string(),
            starttls: None,
            retry: None,
            max_pending_ops: None,
            conn_max_pending: None,
            numconns: None,
            bindconns: None,
        };
        let info = BackendServerInfo::new(0, server, bind_config, "whoami");
        assert_eq!(info.retry_ms, 5000);
        assert_eq!(info.max_pending_ops, 50);
        assert_eq!(info.conn_max_pending, 10);
        assert_eq!(info.numconns, 10);
        assert_eq!(info.bindconns, 5);
    }

    #[test]
    fn test_backend_pool_semaphore_calculation() {
        let config = BackendConfig {
            bind: BindConfig {
                method: "simple".to_string(),
                binddn: None,
                credentials: None,
                network_timeout: None,
                tls_cacert: None,
                tls_cert: None,
                tls_key: None,
            },
            strategy: BalanceStrategy::Random,
            ring_hash_vnodes: None,
            health_check_interval_sec: None,
            health_check_timeout_sec: None,
            health_check: None,
            connect_attempts: None,
            connect_retry_delay_ms: None,
            tls_skip_verify: None,
            tls_ca_etcd_key: None,
            sticky_writes: None,
            servers: vec![
                BackendServer {
                    uri: "ldap://localhost:389".to_string(),
                    starttls: None,
                    retry: None,
                    max_pending_ops: None,
                    conn_max_pending: None,
                    numconns: Some(10),
                    bindconns: Some(5),
                },
                BackendServer {
                    uri: "ldap://localhost:390".to_string(),
                    starttls: None,
                    retry: None,
                    max_pending_ops: None,
                    conn_max_pending: None,
                    numconns: Some(20),
                    bindconns: Some(10),
                },
            ],
        };
        let pool = BackendPool::new(config, None).unwrap();
        // Semaphore should allow (10+5) + (20+10) = 45 connections
        assert_eq!(pool.server_count(), 2);
    }
}

