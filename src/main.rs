use clap::Parser;
use ldap_load_balancer::{ConfigSource, LdapLoadBalancer, Metrics, run_metrics_server};
use ldap_load_balancer::config_source;
use ldap_load_balancer::ldap_handler::LdapHandler;
use ldap_load_balancer::tls;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, error};
use anyhow::{Context, Result};
use tokio_rustls::TlsAcceptor;
use arc_swap::ArcSwap;

#[derive(Parser)]
#[command(name = "ldap-load-balancer")]
#[command(about = "LDAP v3 Load Balancer - Distributes LDAP requests across multiple backend servers")]
struct Args {
    /// Configuration file path (used when etcd is not set)
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// etcd endpoints (e.g. http://127.0.0.1:2379). If set, config is loaded and watched from etcd.
    #[arg(long, value_name = "ENDPOINTS", num_args = 1..)]
    etcd_endpoints: Option<Vec<String>>,

    /// etcd key for YAML config (e.g. /ldap-load-balancer/config). Used with --etcd-endpoints.
    #[arg(long, value_name = "KEY", default_value = "/ldap-load-balancer/config")]
    etcd_config_key: String,

    /// Fallback config file if etcd key is missing or empty. Used with --etcd-endpoints.
    #[arg(long, value_name = "FILE")]
    etcd_fallback_file: Option<PathBuf>,

    /// Use etcd on localhost:12379 (for running outside Docker when etcd is published on 12379). Overrides --etcd-endpoints for connection; ETCD_ENDPOINTS env still wins if set.
    #[arg(long)]
    etcd_endpoints_local: bool,

    /// Listen URL (overrides config; e.g. ldap://:1389)
    #[arg(short = 'l', long, value_name = "URL")]
    listen: Option<String>,

    /// Enable debug logging
    #[arg(short, long)]
    debug: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let log_level = if args.debug { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(format!("ldap_load_balancer={},info", log_level))
        .init();

    info!("Starting LDAP Load Balancer");

    let source = if let Some(mut endpoints) = args.etcd_endpoints {
        if endpoints.is_empty() {
            error!("--etcd-endpoints must not be empty");
            std::process::exit(1);
        }
        if let Ok(env_ep) = std::env::var("ETCD_ENDPOINTS") {
            let overridden: Vec<String> = env_ep
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !overridden.is_empty() {
                info!("etcd endpoints overridden by ETCD_ENDPOINTS env");
                endpoints = overridden;
            }
        } else if args.etcd_endpoints_local {
            endpoints = vec!["http://127.0.0.1:12379".to_string()];
            info!("etcd endpoints set to localhost:12379 (--etcd-endpoints-local)");
        }
        info!("Configuration source: etcd (live reload) key={}", args.etcd_config_key);
        ConfigSource::Etcd {
            endpoints,
            config_key: args.etcd_config_key,
            fallback_file: args.etcd_fallback_file,
        }
    } else if let Some(path) = args.config {
        info!("Configuration source: file {:?}", path);
        ConfigSource::File { path }
    } else {
        error!("Set --config <FILE> or --etcd-endpoints <ENDPOINTS>");
        std::process::exit(1);
    };

    let etcd_endpoints = match &source {
        ConfigSource::Etcd { endpoints, .. } => Some(endpoints.clone()),
        _ => None,
    };
    let live_config = Arc::new(source.load().await?);
    let listen_url = args
        .listen
        .clone()
        .unwrap_or_else(|| live_config.config().listen.url.clone());

    info!("Configuration loaded:");
    info!("  Listen URL: {}", listen_url);
    info!("  Backend servers: {}", live_config.server_count());
    info!("  Proxy AuthZ: {}", live_config.proxyauthz());
    info!("  IO Threads: {}", live_config.config().io_threads.unwrap_or(1));

    let handler = Arc::new(LdapHandler::new(Arc::clone(&live_config)));
    let metrics = Arc::new(Metrics::new());

    if let Some(addr) = live_config.config().metrics_listen.clone() {
        let metrics_for_http = Arc::clone(&metrics);
        let live_config_for_metrics = Arc::clone(&live_config);
        let backend_info = Arc::new(move || {
            let pool = live_config_for_metrics.backend_pool();
            (pool.server_count(), pool.backend_states())
        });
        tokio::spawn(async move {
            if let Err(e) = run_metrics_server(&addr, metrics_for_http, backend_info).await {
                error!("Metrics server error: {}", e);
            }
        });
    }

    let tls_acceptor = {
        let cfg = live_config.config();
        let need_ldaps = listen_url.starts_with("ldaps://");
        let have_tls_config = cfg.tls.as_ref().map(|t| {
            (t.cert_file.is_some() && t.key_file.is_some()) || (t.cert_etcd_key.is_some() && t.key_etcd_key.is_some())
        }).unwrap_or(false);
        if need_ldaps && !have_tls_config {
            anyhow::bail!("LDAPS (ldaps://) requires tls section in config (cert_file/key_file or cert_etcd_key/key_etcd_key)");
        }
        if need_ldaps || have_tls_config {
        let tls_cfg = cfg.tls.as_ref().ok_or_else(|| {
            anyhow::anyhow!("TLS section required (for LDAPS or StartTLS)")
        })?;
        let server_config = if let (Some(cert_key), Some(key_key)) =
            (tls_cfg.cert_etcd_key.as_ref(), tls_cfg.key_etcd_key.as_ref())
        {
            let endpoints = etcd_endpoints.as_ref().ok_or_else(|| {
                anyhow::anyhow!("TLS from etcd (cert_etcd_key/key_etcd_key) requires config source to be etcd")
            })?;
            let mut client = etcd_client::Client::connect(endpoints.clone(), None)
                .await
                .context("Connect to etcd for TLS certs")?;
            tls::load_server_config_from_etcd(
                &mut client,
                cert_key,
                key_key,
                tls_cfg.ca_etcd_key.as_deref(),
            )
            .await?
        } else if let (Some(cert_file), Some(key_file)) =
            (tls_cfg.cert_file.as_ref(), tls_cfg.key_file.as_ref())
        {
            tls::validate_tls_files(cert_file, key_file, tls_cfg.ca_file.as_deref())?;
            tls::load_server_config_from_files(
                cert_file,
                key_file,
                tls_cfg.ca_file.as_deref(),
            )?
        } else {
            anyhow::bail!(
                "LDAPS requires either tls.cert_file and tls.key_file, or tls.cert_etcd_key and tls.key_etcd_key"
            );
        };
        info!("TLS enabled for listener (LDAPS or StartTLS)");
        let acceptor = TlsAcceptor::from(server_config);
        let tls_swap = Arc::new(ArcSwap::from_pointee(acceptor));
        if let (Some(endpoints), Some(cert_key), Some(key_key)) = (
            &etcd_endpoints,
            live_config.config().tls.as_ref().and_then(|t| t.cert_etcd_key.as_ref()),
            live_config.config().tls.as_ref().and_then(|t| t.key_etcd_key.as_ref()),
        ) {
            config_source::spawn_etcd_tls_watch(
                endpoints.clone(),
                cert_key.clone(),
                key_key.clone(),
                live_config.config().tls.as_ref().and_then(|t| t.ca_etcd_key.clone()),
                Arc::clone(&tls_swap),
            );
        }
        Some(tls_swap)
        } else {
            None
        }
    };

    let load_balancer = LdapLoadBalancer::new(listen_url, handler, metrics, tls_acceptor);

    load_balancer.start().await?;

    Ok(())
}

