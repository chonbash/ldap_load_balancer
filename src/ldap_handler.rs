use crate::backend::{BackendConnection, BackendPool};
use crate::config_source::LiveConfig;
use crate::ldap_protocol::{Attribute, SearchResultDone, SearchResultEntry};
use ldap3::controls::{RefreshMode, SyncRequest};
use ldap3::{LdapResult, Scope};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info};
use anyhow::{Context, Result};

pub struct LdapHandler {
    /// Живая конфигурация: пул и proxyauthz обновляются "на лету" при изменении в etcd.
    pub(crate) live_config: Arc<LiveConfig>,
}

impl LdapHandler {
    pub fn new(live_config: Arc<LiveConfig>) -> Self {
        Self { live_config }
    }

    fn backend_pool(&self) -> Arc<BackendPool> {
        self.live_config.backend_pool()
    }

    /// `session_key` is used for ring_hash strategy (e.g. client peer address bytes).
    /// Returns (LdapResult, BackendConnection) so the caller can keep the connection for the session
    /// and use it for subsequent search/modify/add/delete on the same client.
    pub async fn handle_bind(
        &self,
        binddn: &str,
        password: &str,
        session_key: Option<&[u8]>,
    ) -> Result<(LdapResult, BackendConnection)> {
        debug!("Handling BIND request for: {}", binddn);
        let pool = self.backend_pool();
        let mut conn = pool
            .get_connection(true, session_key)
            .await
            .context("Failed to get backend connection")?;

        let result = conn.ldap()
            .simple_bind(binddn, password)
            .await
            .context("Bind operation failed")?;

        info!("BIND successful for: {} on {}", binddn, conn.server_uri());
        Ok((result, conn))
    }

    /// If `session_conn` is Some, use that connection (bound as the client). Otherwise get a new connection from the pool.
    pub async fn handle_search(
        &self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: Vec<&str>,
        session_key: Option<&[u8]>,
        session_conn: Option<&mut BackendConnection>,
    ) -> Result<(Vec<ldap3::SearchEntry>, LdapResult)> {
        debug!("Handling SEARCH request: base={}, filter={}", base, filter);
        let conn = if let Some(c) = session_conn {
            c
        } else {
            let pool = self.backend_pool();
            let mut c = pool
                .get_connection(false, session_key)
                .await
                .context("Failed to get backend connection")?;
            let search_result = c.ldap()
                .search(base, scope, filter, attrs)
                .await
                .context("Search operation failed")?;
            let (rs, result) = search_result.success()?;
            let entries: Vec<ldap3::SearchEntry> = rs
                .into_iter()
                .map(|entry| ldap3::SearchEntry::construct(entry))
                .collect();
            debug!("SEARCH returned {} entries from {}", entries.len(), c.server_uri());
            return Ok((entries, result));
        };
        let search_result = conn.ldap()
            .search(
                base,
                scope,
                filter,
                attrs,
            )
            .await
            .context("Search operation failed")?;

        let (rs, result) = search_result.success()?;
        let entries: Vec<ldap3::SearchEntry> = rs
            .into_iter()
            .map(|entry| ldap3::SearchEntry::construct(entry))
            .collect();

        debug!("SEARCH returned {} entries from {}", entries.len(), conn.server_uri());
        Ok((entries, result))
    }

    pub async fn handle_add(
        &self,
        dn: &str,
        attrs: Vec<(String, Vec<String>)>,
        session_key: Option<&[u8]>,
        session_conn: Option<&mut BackendConnection>,
    ) -> Result<LdapResult> {
        debug!("Handling ADD request: dn={}", dn);
        use std::collections::HashSet;
        let attrs_set: Vec<(String, HashSet<String>)> = attrs
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().collect()))
            .collect();
        let conn = if let Some(c) = session_conn {
            c
        } else {
            let pool = self.backend_pool();
            let mut c = pool.get_connection(false, session_key).await.context("Failed to get backend connection")?;
            let result = c.ldap().add(dn, attrs_set).await.context("Add operation failed")?;
            info!("ADD successful for: {} on {}", dn, c.server_uri());
            return Ok(result);
        };
        let result = conn.ldap().add(dn, attrs_set).await.context("Add operation failed")?;
        info!("ADD successful for: {} on {}", dn, conn.server_uri());
        Ok(result)
    }

    pub async fn handle_modify(
        &self,
        dn: &str,
        modlist: Vec<ldap3::Mod<String>>,
        session_key: Option<&[u8]>,
        session_conn: Option<&mut BackendConnection>,
    ) -> Result<LdapResult> {
        debug!("Handling MODIFY request: dn={}", dn);
        let conn = if let Some(c) = session_conn {
            c
        } else {
            let pool = self.backend_pool();
            let mut c = pool.get_connection(false, session_key).await.context("Failed to get backend connection")?;
            let result = c.ldap().modify(dn, modlist).await.context("Modify operation failed")?;
            info!("MODIFY successful for: {} on {}", dn, c.server_uri());
            return Ok(result);
        };
        let result = conn.ldap().modify(dn, modlist).await.context("Modify operation failed")?;
        info!("MODIFY successful for: {} on {}", dn, conn.server_uri());
        Ok(result)
    }

    pub async fn handle_delete(
        &self,
        dn: &str,
        session_key: Option<&[u8]>,
        session_conn: Option<&mut BackendConnection>,
    ) -> Result<LdapResult> {
        debug!("Handling DELETE request: dn={}", dn);
        let conn = if let Some(c) = session_conn {
            c
        } else {
            let pool = self.backend_pool();
            let mut c = pool.get_connection(false, session_key).await.context("Failed to get backend connection")?;
            let result = c.ldap().delete(dn).await.context("Delete operation failed")?;
            info!("DELETE successful for: {} on {}", dn, c.server_uri());
            return Ok(result);
        };
        let result = conn.ldap().delete(dn).await.context("Delete operation failed")?;
        info!("DELETE successful for: {} on {}", dn, conn.server_uri());
        Ok(result)
    }

    pub async fn handle_modify_dn(
        &self,
        dn: &str,
        newrdn: &str,
        delete_old_rdn: bool,
        new_superior: Option<&str>,
        session_key: Option<&[u8]>,
        session_conn: Option<&mut BackendConnection>,
    ) -> Result<LdapResult> {
        debug!("Handling MODIFYDN request: dn={}, newrdn={}", dn, newrdn);
        let conn = if let Some(c) = session_conn {
            c
        } else {
            let pool = self.backend_pool();
            let mut c = pool.get_connection(false, session_key).await.context("Failed to get backend connection")?;
            let result = c.ldap().modifydn(dn, newrdn, delete_old_rdn, new_superior).await.context("ModifyDN operation failed")?;
            info!("MODIFYDN successful for: {} on {}", dn, c.server_uri());
            return Ok(result);
        };
        let result = conn.ldap().modifydn(dn, newrdn, delete_old_rdn, new_superior).await.context("ModifyDN operation failed")?;
        info!("MODIFYDN successful for: {} on {}", dn, conn.server_uri());
        Ok(result)
    }

    pub async fn handle_compare(
        &self,
        dn: &str,
        attr: &str,
        value: &str,
        session_key: Option<&[u8]>,
        session_conn: Option<&mut BackendConnection>,
    ) -> Result<LdapResult> {
        debug!("Handling COMPARE request: dn={}, attr={}", dn, attr);
        let conn = if let Some(c) = session_conn {
            c
        } else {
            let pool = self.backend_pool();
            let mut c = pool.get_connection(false, session_key).await.context("Failed to get backend connection")?;
            let compare_result = c.ldap().compare(dn, attr, value).await.context("Compare operation failed")?;
            return Ok(compare_result.0.success()?);
        };
        let compare_result = conn.ldap()
            .compare(dn, attr, value)
            .await
            .context("Compare operation failed")?;
        let result = compare_result.0.success()?;

        debug!("COMPARE successful for: {} on {}", dn, conn.server_uri());
        Ok(result)
    }

    // Extended operations require specific Exop types from ldap3
    // This is a placeholder - implement specific extended operations as needed
    // Example: WhoAmI, StartTLS, PasswordModify, etc.
    pub async fn handle_extended_whoami(
        &self,
        session_key: Option<&[u8]>,
        session_conn: Option<&mut BackendConnection>,
    ) -> Result<String> {
        debug!("Handling EXTENDED WhoAmI request");
        use ldap3::exop::WhoAmI;
        let conn = if let Some(c) = session_conn {
            c
        } else {
            let pool = self.backend_pool();
            let mut c = pool.get_connection(false, session_key).await.context("Failed to get backend connection")?;
            let exop_result = c.ldap().extended(WhoAmI).await.context("Extended operation failed")?;
            let (exop, _) = exop_result.success()?;
            let whoami_result = if exop.name.as_ref().map(|s| s.as_str()) == Some("1.3.6.1.4.1.4203.1.11.3") {
                exop.val.as_ref().map(|v| String::from_utf8_lossy(v).to_string()).unwrap_or_else(|| "anonymous".to_string())
            } else {
                "anonymous".to_string()
            };
            return Ok(whoami_result);
        };
        let exop_result = conn.ldap()
            .extended(WhoAmI)
            .await
            .context("Extended operation failed")?;

        let (exop, _ldap_result) = exop_result.success()?;
        
        // Parse WhoAmI from generic Exop
        let whoami_result = if exop.name.as_ref().map(|s| s.as_str()) == Some("1.3.6.1.4.1.4203.1.11.3") {
            // WhoAmI extended operation
            if let Some(val) = exop.val {
                String::from_utf8_lossy(&val).to_string()
            } else {
                "anonymous".to_string()
            }
        } else {
            "anonymous".to_string()
        };

        debug!("EXTENDED WhoAmI successful on {}: {}", conn.server_uri(), whoami_result);
        Ok(whoami_result)
    }

    /// Start a persistent search (RFC 4533 refreshAndPersist). Returns a channel that receives
    /// search result entries and finally a SearchResultDone. The task holds the backend connection.
    /// `session_key` is used for ring_hash strategy (e.g. client peer address bytes).
    pub fn start_persistent_search(
        self: Arc<Self>,
        base: String,
        scope: Scope,
        filter: String,
        attrs: Vec<String>,
        sync_cookie: Option<Vec<u8>>,
        session_key: Option<Vec<u8>>,
    ) -> Result<mpsc::UnboundedReceiver<PersistentSearchItem>> {
        let (tx, rx) = mpsc::unbounded_channel();
        let pool = self.backend_pool().clone();
        tokio::spawn(async move {
            let result = run_persistent_search(pool, base, scope, filter, attrs, sync_cookie, session_key, tx).await;
            if let Err(e) = result {
                tracing::error!("Persistent search error: {}", e);
            }
        });
        Ok(rx)
    }
}

/// Item streamed from a persistent search.
#[derive(Debug)]
pub enum PersistentSearchItem {
    Entry(SearchResultEntry),
    Done(SearchResultDone),
}

async fn run_persistent_search(
    pool: Arc<BackendPool>,
    base: String,
    scope: Scope,
    filter: String,
    attrs: Vec<String>,
    sync_cookie: Option<Vec<u8>>,
    session_key: Option<Vec<u8>>,
    tx: mpsc::UnboundedSender<PersistentSearchItem>,
) -> Result<()> {
    let mut conn = pool
        .get_connection(false, session_key.as_deref())
        .await
        .context("Failed to get backend connection")?;
    let ldap = conn.ldap();
    let sync_request = SyncRequest {
        mode: RefreshMode::RefreshAndPersist,
        cookie: sync_cookie,
        reload_hint: false,
    };
    let attrs_ref: Vec<&str> = attrs.iter().map(String::as_str).collect();
    let mut stream = ldap
        .with_controls(sync_request)
        .streaming_search(&base, scope, &filter, attrs_ref)
        .await
        .context("Persistent search start failed")?;

    loop {
        match stream.next().await {
            Ok(Some(entry)) => {
                if entry.is_intermediate() || entry.is_ref() {
                    continue;
                }
                let search_entry = ldap3::SearchEntry::construct(entry);
                let our_entry = SearchResultEntry {
                    object_name: search_entry.dn,
                    attributes: search_entry
                        .attrs
                        .iter()
                        .map(|(k, v)| Attribute {
                            attr_type: k.clone(),
                            attr_values: v.iter().map(|s| s.as_bytes().to_vec()).collect(),
                        })
                        .collect(),
                };
                if tx.send(PersistentSearchItem::Entry(our_entry)).is_err() {
                    break;
                }
            }
            Ok(None) => break,
            Err(e) => {
                let _ = tx.send(PersistentSearchItem::Done(SearchResultDone {
                    result_code: 80,
                    matched_dn: String::new(),
                    diagnostic_message: e.to_string(),
                }));
                break;
            }
        }
    }

    let result = stream.finish().await;
    let _ = tx.send(PersistentSearchItem::Done(SearchResultDone {
        result_code: result.rc as i32,
        matched_dn: result.matched.clone(),
        diagnostic_message: result.text.clone(),
    }));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::config_source::LiveConfig;

    fn create_test_config() -> Config {
        let yaml = r#"
listen:
  url: "ldap://127.0.0.1:1389"
backend:
  bind:
    method: "simple"
  servers:
    - uri: "ldap://localhost:389"
      numconns: 10
      bindconns: 5
proxyauthz: false
"#;
        Config::from_str(yaml).unwrap()
    }

    #[test]
    fn test_ldap_handler_new() {
        let config = create_test_config();
        let live = LiveConfig::from_config(config).unwrap();
        let handler = LdapHandler::new(Arc::new(live));
        assert_eq!(handler.backend_pool().server_count(), 1);
    }

    #[test]
    fn test_ldap_handler_new_with_proxyauthz() {
        let mut config = create_test_config();
        config.proxyauthz = Some(true);
        let live = LiveConfig::from_config(config).unwrap();
        let handler = LdapHandler::new(Arc::new(live));
        assert_eq!(handler.backend_pool().server_count(), 1);
        assert!(handler.live_config.proxyauthz());
    }

    #[tokio::test]
    async fn test_start_persistent_search_returns_receiver() {
        let config = create_test_config();
        let live = LiveConfig::from_config(config).unwrap();
        let handler = Arc::new(LdapHandler::new(Arc::new(live)));
        let rx = handler
            .start_persistent_search(
                "dc=example,dc=com".to_string(),
                ldap3::Scope::Subtree,
                "(objectClass=*)".to_string(),
                vec![],
                None,
            )
            .unwrap();
        let item = rx.recv().await;
        assert!(item.is_some());
        match item.unwrap() {
            PersistentSearchItem::Entry(_) => {}
            PersistentSearchItem::Done(d) => {
                assert!(d.result_code == 0 || d.result_code != 0);
            }
        }
    }
}

