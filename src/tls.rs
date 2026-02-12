//! TLS server configuration: load certificates from files or etcd, build TlsAcceptor.

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use std::fs;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

/// Build a rustls ServerConfig from PEM certificate and key file paths.
pub fn load_server_config_from_files(
    cert_file: &str,
    key_file: &str,
    _ca_file: Option<&str>,
) -> Result<Arc<rustls::ServerConfig>> {
    let certs = load_certs_from_file(cert_file)?;
    let key = load_private_key_from_file(key_file)?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Build ServerConfig from cert and key")?;
    Ok(Arc::new(config))
}

fn load_certs_from_file(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file = fs::File::open(path).with_context(|| format!("Open cert file: {}", path))?;
    let mut reader = BufReader::new(file);
    let certs: Vec<CertificateDer<'static>> = certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .context("Parse PEM certificates")?;
    if certs.is_empty() {
        anyhow::bail!("No certificates found in {}", path);
    }
    Ok(certs)
}

fn load_private_key_from_file(path: &str) -> Result<PrivateKeyDer<'static>> {
    let file = fs::File::open(path).with_context(|| format!("Open key file: {}", path))?;
    let mut reader = BufReader::new(file);
    let pkcs8: Vec<_> = pkcs8_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .context("Parse PEM PKCS8 keys")?;
    if let Some(key) = pkcs8.into_iter().next() {
        return Ok(key.into());
    }
    let file = fs::File::open(path).with_context(|| format!("Open key file: {}", path))?;
    let mut reader = BufReader::new(file);
    let rsa: Vec<_> = rsa_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .context("Parse PEM RSA keys")?;
    rsa.into_iter()
        .next()
        .map(Into::into)
        .ok_or_else(|| anyhow::anyhow!("No private key found in {}", path))
}

/// Build ServerConfig from PEM bytes (e.g. from etcd).
pub fn load_server_config_from_pem(
    cert_pem: &[u8],
    key_pem: &[u8],
    _ca_pem: Option<&[u8]>,
) -> Result<Arc<rustls::ServerConfig>> {
    let certs: Vec<CertificateDer<'static>> = certs(&mut std::io::Cursor::new(cert_pem))
        .collect::<Result<Vec<_>, _>>()
        .context("Parse PEM certificates")?;
    if certs.is_empty() {
        anyhow::bail!("No certificates in PEM data");
    }
    let mut key = None;
    let pkcs8: Vec<_> = pkcs8_private_keys(&mut std::io::Cursor::new(key_pem))
        .collect::<Result<Vec<_>, _>>()
        .context("Parse PEM PKCS8 key")?;
    if let Some(k) = pkcs8.into_iter().next() {
        key = Some(k.into());
    }
    if key.is_none() {
        let rsa: Vec<_> = rsa_private_keys(&mut std::io::Cursor::new(key_pem))
            .collect::<Result<Vec<_>, _>>()
            .context("Parse PEM RSA key")?;
        if let Some(k) = rsa.into_iter().next() {
            key = Some(k.into());
        }
    }
    let key = key.ok_or_else(|| anyhow::anyhow!("No private key in PEM data"))?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Build ServerConfig from PEM")?;
    Ok(Arc::new(config))
}

/// Check that cert and key files exist and are readable (for startup validation).
pub fn validate_tls_files(cert_file: &str, key_file: &str, ca_file: Option<&str>) -> Result<()> {
    if !Path::new(cert_file).exists() {
        anyhow::bail!("TLS cert file not found: {}", cert_file);
    }
    if !Path::new(key_file).exists() {
        anyhow::bail!("TLS key file not found: {}", key_file);
    }
    if let Some(ca) = ca_file {
        if !Path::new(ca).exists() {
            anyhow::bail!("TLS CA file not found: {}", ca);
        }
    }
    load_server_config_from_files(cert_file, key_file, ca_file)?;
    Ok(())
}

/// Fetch PEM from etcd and build ServerConfig. Values are expected to be UTF-8 PEM.
pub async fn load_server_config_from_etcd(
    client: &mut etcd_client::Client,
    cert_key: &str,
    key_key: &str,
    ca_key: Option<&str>,
) -> Result<Arc<rustls::ServerConfig>> {
    let cert_resp = client.get(cert_key, None).await.context("etcd get cert key")?;
    let cert_pem = cert_resp
        .kvs()
        .first()
        .and_then(|kv| kv.value_str().ok())
        .ok_or_else(|| anyhow::anyhow!("etcd key {} missing or empty", cert_key))?;
    let key_resp = client.get(key_key, None).await.context("etcd get key key")?;
    let key_pem = key_resp
        .kvs()
        .first()
        .and_then(|kv| kv.value_str().ok())
        .ok_or_else(|| anyhow::anyhow!("etcd key {} missing or empty", key_key))?;
    let ca_pem = if let Some(k) = ca_key {
        let r = client.get(k, None).await.context("etcd get ca key")?;
        r.kvs()
            .first()
            .and_then(|kv| kv.value_str().ok())
            .map(|s| s.as_bytes().to_vec())
    } else {
        None
    };
    load_server_config_from_pem(
        cert_pem.as_bytes(),
        key_pem.as_bytes(),
        ca_pem.as_deref(),
    )
}
