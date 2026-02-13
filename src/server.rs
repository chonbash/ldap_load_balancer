use crate::backend::{BackendConnection, BackendSession, BackendStream};
use crate::ldap_handler::{LdapHandler, PersistentSearchItem};
use crate::metrics::Metrics;
use crate::ldap_protocol::{
    get_sync_request_control, parse_ldap_message_header, scope_to_ldap3, *,
    LDAP_TAG_BIND_RESPONSE,
    LDAP_TAG_SEARCH_RESULT_DONE,
    LDAP_TAG_MODIFY_RESPONSE,
    LDAP_TAG_ADD_RESPONSE,
    LDAP_TAG_DEL_RESPONSE,
    LDAP_TAG_MODIFY_DN_RESPONSE,
    LDAP_TAG_COMPARE_RESPONSE,
    LDAP_TAG_EXTENDED_RESPONSE,
    BerWriter,
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info, warn, debug};
use anyhow::{Context, Result};
use std::net::SocketAddr;
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncWrite};
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use arc_swap::ArcSwap;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

/// OID for StartTLS extended operation (RFC 4511).
pub const START_TLS_OID: &str = "1.3.6.1.4.1.1466.20037";

/// Client stream: either plain TCP or TLS-wrapped. Used so we can support both ldap:// and ldaps:// and later StartTLS upgrade.
pub enum ClientStream {
    Tcp(TcpStream),
    Tls(TlsStream<TcpStream>),
}

impl AsyncRead for ClientStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            ClientStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            ClientStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ClientStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            ClientStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            ClientStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            ClientStream::Tcp(s) => Pin::new(s).poll_flush(cx),
            ClientStream::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            ClientStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            ClientStream::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Read half of ClientStream (for persistent search).
pub enum ClientReadHalf {
    Tcp(tokio::net::tcp::OwnedReadHalf),
    Tls(tokio::io::ReadHalf<TlsStream<TcpStream>>),
}

/// Write half of ClientStream (for persistent search).
pub enum ClientWriteHalf {
    Tcp(tokio::net::tcp::OwnedWriteHalf),
    Tls(tokio::io::WriteHalf<TlsStream<TcpStream>>),
}

impl AsyncRead for ClientReadHalf {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            ClientReadHalf::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            ClientReadHalf::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ClientWriteHalf {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            ClientWriteHalf::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            ClientWriteHalf::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            ClientWriteHalf::Tcp(s) => Pin::new(s).poll_flush(cx),
            ClientWriteHalf::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            ClientWriteHalf::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            ClientWriteHalf::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl ClientStream {
    pub fn into_split(self) -> (ClientReadHalf, ClientWriteHalf) {
        match self {
            ClientStream::Tcp(s) => {
                let (r, w) = s.into_split();
                (ClientReadHalf::Tcp(r), ClientWriteHalf::Tcp(w))
            }
            ClientStream::Tls(s) => {
                let (r, w) = tokio::io::split(s);
                (ClientReadHalf::Tls(r), ClientWriteHalf::Tls(w))
            }
        }
    }
}

/// Parsed message plus raw bytes (for proxy: forward bytes unchanged to backend).
pub struct MessageWithRaw {
    pub message: LdapMessage,
    pub raw: Vec<u8>,
}

/// Result of trying to parse one LDAP message from the buffer.
pub enum TryParseResult {
    /// Not enough data yet.
    Incomplete,
    /// Successfully parsed message and its raw bytes.
    Message(MessageWithRaw),
    /// Parse failed; consume `consume` bytes and send error response (message_id, response_tag).
    ParseError {
        message_id: i32,
        response_tag: u8,
        consume: usize,
    },
}

pub struct LdapLoadBalancer {
    listen_url: String,
    handler: Arc<LdapHandler>,
    metrics: Arc<Metrics>,
    /// When Some, LDAPS is enabled; use .load() to get current TlsAcceptor (supports hot reload from etcd).
    tls_acceptor: Option<Arc<ArcSwap<TlsAcceptor>>>,
}

impl LdapLoadBalancer {
    pub fn new(
        listen_url: String,
        handler: Arc<LdapHandler>,
        metrics: Arc<Metrics>,
        tls_acceptor: Option<Arc<ArcSwap<TlsAcceptor>>>,
    ) -> Self {
        Self {
            listen_url,
            handler,
            metrics,
            tls_acceptor,
        }
    }

    pub async fn start(&self) -> Result<()> {
        let listen_url = &self.listen_url;
        let addr = parse_listen_url(listen_url)?;
        
        info!("Starting LDAP Load Balancer on {}", addr);
        
        let listener = TcpListener::bind(&addr)
            .await
            .with_context(|| format!("Failed to bind to {}", addr))?;

        info!("LDAP Load Balancer listening on {}", addr);
        info!("Backend servers: {}", self.handler.live_config.server_count());

        let tls_acceptor = self.tls_acceptor.clone();

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    debug!("New connection from {}", peer_addr);
                    let handler = Arc::clone(&self.handler);
                    let metrics = Arc::clone(&self.metrics);
                    metrics.inc_connections();
                    let acceptor = tls_acceptor.clone();
                    
                    tokio::spawn(async move {
                        let client_stream = if let Some(ref swap) = acceptor {
                            let acceptor = swap.load();
                            match acceptor.accept(stream).await {
                                Ok(tls_stream) => ClientStream::Tls(tls_stream),
                                Err(e) => {
                                    error!("TLS handshake failed for {}: {}", peer_addr, e);
                                    return;
                                }
                            }
                        } else {
                            ClientStream::Tcp(stream)
                        };
                        if let Err(e) = handle_client(client_stream, peer_addr, handler, metrics, acceptor).await {
                            error!("Error handling client {}: {}", peer_addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }
}

fn parse_listen_url(url: &str) -> Result<SocketAddr> {
    // Parse ldap://host:port or ldaps://host:port
    let url = url.strip_prefix("ldap://")
        .or_else(|| url.strip_prefix("ldaps://"))
        .ok_or_else(|| anyhow::anyhow!("Invalid URL scheme, expected ldap:// or ldaps://"))?;

    // Remove leading slashes if present
    let url = url.trim_start_matches('/');
    
    // Parse host:port
    if url.starts_with(':') {
        // Just port specified, bind to all interfaces
        let port: u16 = url.trim_start_matches(':')
            .parse()
            .context("Invalid port number")?;
        Ok(SocketAddr::from(([0, 0, 0, 0], port)))
    } else {
        url.parse()
            .with_context(|| format!("Failed to parse address: {}", url))
    }
}

async fn handle_client(
    mut stream: ClientStream,
    peer_addr: SocketAddr,
    handler: Arc<LdapHandler>,
    metrics: Arc<Metrics>,
    tls_acceptor: Option<Arc<ArcSwap<TlsAcceptor>>>,
) -> Result<()> {
    debug!("Handling client connection from {}", peer_addr);
    let mut backend_session: Option<BackendSession> = None;
    let mut backend_read_buf = BytesMut::with_capacity(4096);
    let mut buffer = BytesMut::with_capacity(4096);

    'read_loop: loop {
        // Read data from client
        let mut read_buf = vec![0u8; 4096];
        match stream.read(&mut read_buf).await {
            Ok(0) => {
                debug!("Client {} disconnected", peer_addr);
                break;
            }
            Ok(n) => {
                buffer.extend_from_slice(&read_buf[..n]);
                let mut starttls_upgraded = false;
                loop {
                    let parse_result = match try_parse_message(&mut buffer) {
                        Ok(r) => r,
                        Err(e) => {
                            warn!("Invalid LDAP message from {}: {}", peer_addr, e);
                            let err_data = encode_error_response(
                                0,
                                LDAP_TAG_BIND_RESPONSE,
                                2, // protocolError
                                "",
                                "Invalid message",
                            ).unwrap_or_default();
                            if !err_data.is_empty() {
                                let _ = stream.write_all(&err_data).await;
                                let _ = stream.flush().await;
                            }
                            break;
                        }
                    };
                    match parse_result {
                        TryParseResult::Incomplete => break,
                        TryParseResult::ParseError {
                            message_id,
                            response_tag,
                            consume,
                        } => {
                            metrics.inc_parse_error();
                            let first_byte = buffer.get(0).copied().unwrap_or(0);
                            debug!(
                                "Parse error from {} (first_byte=0x{:02X}, consume={}); sending protocolError",
                                peer_addr, first_byte, consume,
                            );
                            let err_data = encode_error_response(
                                message_id,
                                response_tag,
                                2, // protocolError
                                "",
                                "Failed to parse LDAP message",
                            ).or_else(|e| {
                                warn!("Failed to encode parse error response: {}", e);
                                encode_error_response(0, LDAP_TAG_BIND_RESPONSE, 2, "", "Parse error")
                            }).unwrap_or_default();
                            if !err_data.is_empty() {
                                if let Err(e) = stream.write_all(&err_data).await {
                                    error!("Failed to send parse error to {}: {}", peer_addr, e);
                                    break;
                                }
                                if let Err(e) = stream.flush().await {
                                    error!("Failed to flush parse error to {}: {}", peer_addr, e);
                                    break;
                                }
                                debug!("Sent protocolError to {} for unparseable message", peer_addr);
                            } else {
                                error!("Could not encode parse error response for {}; dropping malformed message", peer_addr);
                            }
                            let _ = buffer.split_to(consume);
                        }
                        TryParseResult::Message(mwr) => {
                            let message = &mwr.message;
                            debug!("Parsed LDAP message with ID: {}", message.message_id);
                            let metric_op = metric_op_name(&message.protocol_op);
                            let start = Instant::now();

                            // AbandonRequest: no response per RFC 4511
                            if let ProtocolOp::AbandonRequest(to_abandon) = message.protocol_op {
                                debug!("Abandon request for msgid {} (ignored)", to_abandon);
                                continue;
                            }

                            if let ProtocolOp::SearchRequest(ref search_req) = message.protocol_op {
                                if let Some(sync_ctrl) = get_sync_request_control(message.controls.as_ref().map(|v| v.as_slice())) {
                                    if sync_ctrl.is_refresh_and_persist() {
                                        let message_id = message.message_id;
                                        let base = search_req.base_object.clone();
                                        let scope = scope_to_ldap3(search_req.scope);
                                        let filter = search_req.filter.to_ldap_string();
                                        let attrs = search_req.attributes.clone();
                                        let cookie = sync_ctrl.cookie.clone();
                                        let session_key = Some(peer_addr.to_string().into_bytes());
                                        match handler.clone().start_persistent_search(base, scope, filter, attrs, cookie, session_key) {
                                            Ok(mut rx) => {
                                                let (mut rd, mut wr) = stream.into_split();
                                                if let Err(e) = run_persistent_search_loop(&mut rd, &mut wr, message_id, &mut rx, &peer_addr).await {
                                                    error!("Persistent search loop error {}: {}", peer_addr, e);
                                                }
                                                return Ok(());
                                            }
                                            Err(e) => {
                                                error!("Failed to start persistent search: {}", e);
                                                let err_data = encode_error_response(
                                                    message_id,
                                                    LDAP_TAG_SEARCH_RESULT_DONE,
                                                    80,
                                                    "",
                                                    &format!("Persistent search failed: {}", e),
                                                ).or_else(|_| encode_error_response(0, LDAP_TAG_SEARCH_RESULT_DONE, 80, "", "Persistent search failed")).unwrap_or_default();
                                                if !err_data.is_empty() {
                                                    if let Err(e2) = stream.write_all(&err_data).await {
                                                        error!("Failed to send persistent search error to {}: {}", peer_addr, e2);
                                                    }
                                                    let _ = stream.flush().await;
                                                }
                                            }
                                        }
                                        continue;
                                    }
                                }
                            }

                            // StartTLS: handle locally (do not proxy). RFC 4511.
                            if let ProtocolOp::ExtendedRequest(ref ext_req) = message.protocol_op {
                                if ext_req.request_name == START_TLS_OID {
                                    let message_id = message.message_id;
                                    if let ClientStream::Tls(_) = &stream {
                                        let err_data = encode_error_response(
                                            message_id,
                                            LDAP_TAG_EXTENDED_RESPONSE,
                                            2, // protocolError
                                            "",
                                            "StartTLS not permitted on secure connection",
                                        ).unwrap_or_default();
                                        if !err_data.is_empty() {
                                            let _ = stream.write_all(&err_data).await;
                                            let _ = stream.flush().await;
                                        }
                                        if let Some(op) = metric_op {
                                            metrics.inc_error(op);
                                        }
                                        continue;
                                    }
                                    let acceptor = match &tls_acceptor {
                                        Some(a) => a.load(),
                                        None => {
                                            let err_data = encode_error_response(
                                                message_id,
                                                LDAP_TAG_EXTENDED_RESPONSE,
                                                53, // unwillingToPerform
                                                "",
                                                "StartTLS not configured",
                                            ).unwrap_or_default();
                                            if !err_data.is_empty() {
                                                let _ = stream.write_all(&err_data).await;
                                                let _ = stream.flush().await;
                                            }
                                            if let Some(op) = metric_op {
                                                metrics.inc_error(op);
                                            }
                                            continue;
                                        }
                                    };
                                    let response = ExtendedResponse {
                                        result_code: 0,
                                        matched_dn: String::new(),
                                        diagnostic_message: String::new(),
                                        response_name: None,
                                        response_value: None,
                                    };
                                    let ldap_response = LdapMessage {
                                        message_id,
                                        protocol_op: ProtocolOp::ExtendedResponse(response),
                                        controls: None,
                                    };
                                    let data = match encode_ldap_message(&ldap_response) {
                                        Ok(d) => d,
                                        Err(e) => {
                                            error!("Failed to encode StartTLS response: {}", e);
                                            if let Some(op) = metric_op {
                                                metrics.inc_error(op);
                                            }
                                            continue;
                                        }
                                    };
                                    if let Err(e) = stream.write_all(&data).await {
                                        error!("Failed to send StartTLS response to {}: {}", peer_addr, e);
                                        if let Some(op) = metric_op {
                                            metrics.inc_error(op);
                                        }
                                        break;
                                    }
                                    if let Err(e) = stream.flush().await {
                                        error!("Failed to flush StartTLS response to {}: {}", peer_addr, e);
                                        if let Some(op) = metric_op {
                                            metrics.inc_error(op);
                                        }
                                        break;
                                    }
                                    stream = match stream {
                                        ClientStream::Tcp(tcp_stream) => {
                                            match acceptor.accept(tcp_stream).await {
                                                Ok(tls_stream) => {
                                                    starttls_upgraded = true;
                                                    debug!("StartTLS upgrade completed for {}", peer_addr);
                                                    if let Some(op) = metric_op {
                                                        metrics.observe_duration(op, start.elapsed());
                                                        metrics.inc_request(op);
                                                    }
                                                    ClientStream::Tls(tls_stream)
                                                }
                                                Err(e) => {
                                                    error!("StartTLS handshake failed for {}: {}", peer_addr, e);
                                                    if let Some(op) = metric_op {
                                                        metrics.inc_error(op);
                                                    }
                                                    break 'read_loop;
                                                }
                                            }
                                        }
                                        _ => unreachable!("StartTLS only runs when stream is Tcp"),
                                    };
                                    if starttls_upgraded {
                                        break;
                                    }
                                    continue;
                                }
                            }

                            // Proxy: forward request bytes to backend, forward response bytes to client unchanged
                            let pool = handler.live_config.backend_pool();
                            let session = if let Some(s) = &mut backend_session {
                                s
                            } else {
                                let cfg = handler.live_config.config();
                                let attempts = cfg.backend.connect_attempts.unwrap_or(3);
                                let retry_delay = Duration::from_millis(cfg.backend.connect_retry_delay_ms.unwrap_or(50));
                                let hash_key = peer_addr.to_string().into_bytes();
                                let mut last_err = None;
                                for attempt in 0..attempts {
                                    match pool
                                        .open_raw_stream(Some(hash_key.as_slice()))
                                        .await
                                        .with_context(|| format!("Backend connect for {} (attempt {})", peer_addr, attempt + 1))
                                    {
                                        Ok(s) => {
                                            debug!("Backend connection opened for {} (proxy)", peer_addr);
                                            backend_session = Some(s);
                                            last_err = None;
                                            break;
                                        }
                                        Err(e) => {
                                            error!("Backend connect failed for {} (attempt {}): {:#}", peer_addr, attempt + 1, e);
                                            last_err = Some(e);
                                            if attempt + 1 < attempts {
                                                tokio::time::sleep(retry_delay).await;
                                            }
                                        }
                                    }
                                }
                                if backend_session.is_some() {
                                    backend_session.as_mut().unwrap()
                                } else {
                                    if let Some(op) = metric_op {
                                        metrics.observe_duration(op, start.elapsed());
                                    }
                                    return Err(last_err.unwrap_or_else(|| anyhow::anyhow!("No backend")));
                                }
                            };
                            let backend_uri = session.uri.clone();
                            let op_name = proxy_op_name(&message.protocol_op);
                            debug!("Proxy: {} (msgid {}) from {}", op_name, message.message_id, peer_addr);
                            if let Err(e) = session.stream.write_all(&mwr.raw).await {
                                error!("Failed to forward request to backend {}: {}", peer_addr, e);
                                if let Some(op) = metric_op {
                                    metrics.inc_error(op);
                                }
                                break;
                            }
                            if let ProtocolOp::UnbindRequest = message.protocol_op {
                                backend_session = None;
                            } else {
                                loop {
                                    let resp = match read_one_ldap_message(&mut session.stream, &mut backend_read_buf).await {
                                        Ok(r) => r,
                                        Err(e) => {
                                            error!("Failed to read response from backend {}: {}", peer_addr, e);
                                            if let Some(op) = metric_op {
                                                metrics.inc_error(op);
                                            }
                                            break;
                                        }
                                    };
                                    if let Err(e) = stream.write_all(&resp).await {
                                        error!("Failed to send response to client {}: {}", peer_addr, e);
                                        if let Some(op) = metric_op {
                                            metrics.inc_error(op);
                                        }
                                        break;
                                    }
                                    let (_, tag) = parse_ldap_message_header(&resp).unwrap_or((0, 0));
                                    if is_final_response_tag(tag) {
                                        break;
                                    }
                                }
                            }
                            if let Err(e) = stream.flush().await {
                                error!("Error flushing to {}: {}", peer_addr, e);
                                if let Some(op) = metric_op {
                                    metrics.inc_error(op);
                                }
                                break;
                            }
                            if let Some(op) = metric_op {
                                metrics.observe_duration(op, start.elapsed());
                                metrics.inc_request(op);
                                metrics.inc_backend_request(&backend_uri, op);
                            }
                        }
                    }
                }
                if starttls_upgraded {
                    continue 'read_loop;
                }
            }
            Err(e) => {
                error!("Error reading from client {}: {}", peer_addr, e);
                break;
            }
        }
    }

    Ok(())
}

async fn run_persistent_search_loop(
    rd: &mut ClientReadHalf,
    wr: &mut ClientWriteHalf,
    message_id: i32,
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<PersistentSearchItem>,
    _peer_addr: &SocketAddr,
) -> Result<()> {
    let mut read_buffer = BytesMut::with_capacity(4096);
    loop {
        tokio::select! {
            item = rx.recv() => {
                match item {
                    Some(PersistentSearchItem::Entry(entry)) => {
                        let msg = LdapMessage {
                            message_id,
                            protocol_op: ProtocolOp::SearchResultEntry(entry),
                            controls: None,
                        };
                        let data = encode_ldap_message(&msg)?;
                        wr.write_all(&data).await?;
                        wr.flush().await?;
                    }
                    Some(PersistentSearchItem::Done(done)) => {
                        let msg = LdapMessage {
                            message_id,
                            protocol_op: ProtocolOp::SearchResultDone(done),
                            controls: None,
                        };
                        let data = encode_ldap_message(&msg)?;
                        wr.write_all(&data).await?;
                        wr.flush().await?;
                        break;
                    }
                    None => break,
                }
            }
            n = rd.read_buf(&mut read_buffer) => {
                let n = n?;
                if n == 0 {
                    break;
                }
                loop {
                    let parse_result = match try_parse_message(&mut read_buffer) {
                        Ok(r) => r,
                        Err(_) => {
                            let err = encode_error_response(
                                message_id,
                                LDAP_TAG_SEARCH_RESULT_DONE,
                                2,
                                "",
                                "Invalid message",
                            ).unwrap_or_default();
                            let _ = wr.write_all(&err).await;
                            let _ = wr.flush().await;
                            break;
                        }
                    };
                    match parse_result {
                        TryParseResult::Incomplete => break,
                        TryParseResult::ParseError {
                            message_id: mid,
                            response_tag,
                            consume,
                        } => {
                            let err = encode_error_response(mid, response_tag, 2, "", "Failed to parse LDAP message")
                                .unwrap_or_default();
                            if !err.is_empty() {
                                let _ = wr.write_all(&err).await;
                                let _ = wr.flush().await;
                            }
                            let _ = read_buffer.split_to(consume);
                        }
                        TryParseResult::Message(mwr) => {
                            match mwr.message.protocol_op {
                                ProtocolOp::UnbindRequest => {
                                    debug!("Persistent search: client sent Unbind");
                                    return Ok(());
                                }
                                ProtocolOp::AbandonRequest(to_abandon) => {
                                    debug!("Persistent search: client sent Abandon for msgid {} (ignored)", to_abandon);
                                    // No response per RFC 4511; continue receiving
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Human-readable operation name for proxy logs.
fn proxy_op_name(op: &ProtocolOp) -> &'static str {
    match op {
        ProtocolOp::BindRequest(_) => "BIND",
        ProtocolOp::SearchRequest(_) => "SEARCH",
        ProtocolOp::ModifyRequest(_) => "MODIFY",
        ProtocolOp::AddRequest(_) => "ADD",
        ProtocolOp::DelRequest(_) => "DELETE",
        ProtocolOp::ModifyDNRequest(_) => "MODIFYDN",
        ProtocolOp::CompareRequest(_) => "COMPARE",
        ProtocolOp::ExtendedRequest(_) => "EXTENDED",
        ProtocolOp::UnbindRequest => "UNBIND",
        ProtocolOp::AbandonRequest(_) => "ABANDON",
        _ => "OP",
    }
}

/// Имя операции для метрик (ldap_lb_requests_total, duration). None для Unbind — не считаем.
fn metric_op_name(op: &ProtocolOp) -> Option<&'static str> {
    match op {
        ProtocolOp::BindRequest(_) => Some("bind"),
        ProtocolOp::SearchRequest(_) => Some("search"),
        ProtocolOp::ModifyRequest(_) => Some("modify"),
        ProtocolOp::AddRequest(_) => Some("add"),
        ProtocolOp::DelRequest(_) => Some("delete"),
        ProtocolOp::ModifyDNRequest(_) => Some("modify_dn"),
        ProtocolOp::CompareRequest(_) => Some("compare"),
        ProtocolOp::ExtendedRequest(_) => Some("extended"),
        ProtocolOp::UnbindRequest => None,
        ProtocolOp::AbandonRequest(_) => None,
        _ => Some("other"),
    }
}

/// Tags that indicate the final response for a request (one response per operation, or last of many for Search).
fn is_final_response_tag(tag: u8) -> bool {
    matches!(tag,
        0x61 | 0x65 | 0x67 | 0x69 | 0x6B | 0x6D | 0x6F | 0x78
        // BindResponse, SearchResultDone, ModifyResponse, AddResponse, DelResponse, ModifyDNResponse, CompareResponse, ExtendedResponse
    )
}

/// Read one complete LDAP (BER) message from stream into buf, return message bytes.
async fn read_one_ldap_message(
    stream: &mut BackendStream,
    buf: &mut BytesMut,
) -> Result<Vec<u8>> {
    let mut read_buf = [0u8; 4096];
    loop {
        if buf.len() >= 2 {
            let first_byte = buf[1];
            let total_length: Option<usize> = if (first_byte & 0x80) == 0 {
                Some(2 + first_byte as usize)
            } else {
                let length_bytes = (first_byte & 0x7F) as usize;
                if length_bytes == 0 || length_bytes > 4 || buf.len() < 2 + length_bytes {
                    None
                } else {
                    let mut length = 0usize;
                    for i in 0..length_bytes {
                        length = (length << 8) | buf[2 + i] as usize;
                    }
                    Some(2 + length_bytes + length)
                }
            };
            if let Some(total) = total_length {
                if buf.len() >= total {
                    let msg = buf[..total].to_vec();
                    let _ = buf.split_to(total);
                    return Ok(msg);
                }
            }
        }
        let n = stream.read(&mut read_buf).await?;
        if n == 0 {
            anyhow::bail!("Backend connection closed");
        }
        buf.extend_from_slice(&read_buf[..n]);
    }
}

fn response_tag_for_request(request_tag: u8) -> u8 {
    match request_tag {
        0x60 => LDAP_TAG_BIND_RESPONSE,           // BindRequest
        0x63 => LDAP_TAG_SEARCH_RESULT_DONE,      // SearchRequest
        0x66 => LDAP_TAG_MODIFY_RESPONSE,         // ModifyRequest
        0x68 => LDAP_TAG_ADD_RESPONSE,            // AddRequest
        0x4A => LDAP_TAG_DEL_RESPONSE,            // DelRequest
        0x6C => LDAP_TAG_MODIFY_DN_RESPONSE,     // ModifyDNRequest
        0x6E => LDAP_TAG_COMPARE_RESPONSE,       // CompareRequest
        0x77 => LDAP_TAG_EXTENDED_RESPONSE,      // ExtendedRequest
        _ => LDAP_TAG_BIND_RESPONSE,             // fallback so we can send an error
    }
}

/// Returns the response tag for the given operation (for error responses). None for UnbindRequest (no response).
#[allow(dead_code)]
fn response_tag_for_protocol_op(op: &ProtocolOp) -> Option<u8> {
    match op {
        ProtocolOp::BindRequest(_) => Some(LDAP_TAG_BIND_RESPONSE),
        ProtocolOp::SearchRequest(_) => Some(LDAP_TAG_SEARCH_RESULT_DONE),
        ProtocolOp::ModifyRequest(_) => Some(LDAP_TAG_MODIFY_RESPONSE),
        ProtocolOp::AddRequest(_) => Some(LDAP_TAG_ADD_RESPONSE),
        ProtocolOp::DelRequest(_) => Some(LDAP_TAG_DEL_RESPONSE),
        ProtocolOp::ModifyDNRequest(_) => Some(LDAP_TAG_MODIFY_DN_RESPONSE),
        ProtocolOp::CompareRequest(_) => Some(LDAP_TAG_COMPARE_RESPONSE),
        ProtocolOp::ExtendedRequest(_) => Some(LDAP_TAG_EXTENDED_RESPONSE),
        ProtocolOp::UnbindRequest => None,
        ProtocolOp::AbandonRequest(_) => None,
        _ => Some(LDAP_TAG_BIND_RESPONSE), // fallback for any other (shouldn't be request types)
    }
}

/// Top-level LDAP message is always a SEQUENCE (BER tag 0x30). If the stream
/// starts with another tag (e.g. 0x04 OCTET STRING), we're either seeing
/// invalid client data or the remainder of a message after a framing error.
const LDAP_MESSAGE_SEQUENCE_TAG: u8 = 0x30;

fn try_parse_message(buffer: &mut BytesMut) -> Result<TryParseResult> {
    if buffer.len() < 2 {
        return Ok(TryParseResult::Incomplete);
    }

    let first_byte = buffer[0];
    // Unwrap OCTET STRING–wrapped LDAP: some clients send 0x04 <len> <LDAP message (0x30...)>.
    if first_byte == 0x04 && buffer.len() >= 2 {
        let len_byte = buffer[1];
        let outer_inner = if (len_byte & 0x80) == 0 {
            let content_len = len_byte as usize;
            Some((2 + content_len, 2usize))
        } else {
            let length_bytes = (len_byte & 0x7F) as usize;
            if length_bytes == 0 || length_bytes > 4 {
                None
            } else if buffer.len() < 2 + length_bytes {
                return Ok(TryParseResult::Incomplete);
            } else {
                let mut content_len = 0usize;
                for i in 0..length_bytes {
                    content_len = (content_len << 8) | buffer[2 + i] as usize;
                }
                let start = 2 + length_bytes;
                Some((start + content_len, start))
            }
        };
        if let Some((outer_total, inner_start)) = outer_inner {
            if buffer.len() >= outer_total {
                let inner = &buffer[inner_start..outer_total];
                match parse_ldap_message(inner) {
                    Ok(msg) => {
                        let raw = inner.to_vec();
                        let _ = buffer.split_to(outer_total);
                        return Ok(TryParseResult::Message(MessageWithRaw { message: msg, raw }));
                    }
                    Err(e) => {
                        let hex_preview: String = inner
                            .iter()
                            .take(64)
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<_>>()
                            .join(" ");
                        warn!(
                            "Failed to parse 0x04-wrapped LDAP message: {} (inner first 64 bytes: {})",
                            e, hex_preview
                        );
                    }
                }
                // Inner is not valid LDAP; consume whole TLV and report one error
                let (message_id, request_tag) = parse_ldap_message_header(inner).unwrap_or((0, 0x60));
                let response_tag = response_tag_for_request(request_tag);
                let _ = buffer.split_to(outer_total);
                return Ok(TryParseResult::ParseError {
                    message_id,
                    response_tag,
                    consume: outer_total,
                });
            }
            return Ok(TryParseResult::Incomplete);
        }
    }
    if first_byte != LDAP_MESSAGE_SEQUENCE_TAG {
        return Ok(TryParseResult::ParseError {
            message_id: 0,
            response_tag: LDAP_TAG_BIND_RESPONSE,
            consume: 1,
        });
    }

    // Check if we have at least the tag and length
    let mut cursor = std::io::Cursor::new(&buffer[..]);
    let mut tag_buf = [0u8; 1];
    std::io::Read::read_exact(&mut cursor, &mut tag_buf)?;
    
    // Read length
    let mut length_buf = [0u8; 1];
    std::io::Read::read_exact(&mut cursor, &mut length_buf)?;
    let first_byte = length_buf[0];
    
    let total_length = if (first_byte & 0x80) == 0 {
        // Short form
        let content_length = first_byte as usize;
        2 + content_length
    } else {
        // Long form
        let length_bytes = (first_byte & 0x7F) as usize;
        if length_bytes == 0 || length_bytes > 4 {
            anyhow::bail!("Invalid length encoding");
        }
        
        if buffer.len() < 2 + length_bytes {
            return Ok(TryParseResult::Incomplete);
        }
        
        let mut length = 0usize;
        for i in 0..length_bytes {
            length = (length << 8) | buffer[2 + i] as usize;
        }
        2 + length_bytes + length
    };
    
    if buffer.len() < total_length {
        // Not enough data yet
        return Ok(TryParseResult::Incomplete);
    }
    
    let slice = &buffer[..total_length];
    match parse_ldap_message(slice) {
        Ok(msg) => {
            let raw = buffer[..total_length].to_vec();
            let _ = buffer.split_to(total_length);
            Ok(TryParseResult::Message(MessageWithRaw { message: msg, raw }))
        }
        Err(e) => {
            let hex_preview: String = slice
                .iter()
                .take(64)
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");
            warn!(
                "Failed to parse LDAP message: {} (first 64 bytes: {})",
                e, hex_preview
            );
            let (message_id, request_tag) = parse_ldap_message_header(slice).unwrap_or((0, 0x60));
            let response_tag = response_tag_for_request(request_tag);
            Ok(TryParseResult::ParseError {
                message_id,
                response_tag,
                consume: total_length,
            })
        }
    }
}

#[allow(dead_code)]
async fn process_ldap_message(
    handler: &LdapHandler,
    metrics: &Metrics,
    message: LdapMessage,
    peer_addr: &SocketAddr,
    session_conn: &mut Option<BackendConnection>,
) -> Result<Option<Vec<u8>>> {
    let message_id = message.message_id;
    let session_key = peer_addr.to_string().into_bytes();

    match message.protocol_op {
        ProtocolOp::BindRequest(bind_req) => {
            debug!("Processing BIND request for: {}", bind_req.name);

            let password = match &bind_req.authentication {
                BindAuthentication::Simple(pwd) => pwd.clone(),
                BindAuthentication::Sasl { .. } => {
                    // SASL not fully supported yet
                    return Ok(Some(encode_error_response(
                        message_id,
                        LDAP_TAG_BIND_RESPONSE,
                        7, // authMethodNotSupported
                        "",
                        "SASL authentication not yet supported",
                    )?));
                }
            };

            let start = Instant::now();
            let bind_result = handler.handle_bind(&bind_req.name, &password, Some(session_key.as_slice())).await;
            metrics.observe_duration("bind", start.elapsed());
            match bind_result {
                Ok((result, conn)) => {
                    metrics.inc_request("bind");
                    *session_conn = Some(conn);
                    let response = BindResponse {
                        result_code: result.rc as i32,
                        matched_dn: result.matched.clone(),
                        diagnostic_message: result.text.clone(),
                    };
                    
                    let ldap_response = LdapMessage {
                        message_id,
                        protocol_op: ProtocolOp::BindResponse(response),
                        controls: None,
                    };
                    
                    Ok(Some(encode_ldap_message(&ldap_response)?))
                }
                Err(e) => {
                    metrics.inc_error("bind");
                    error!("Bind failed: {}", e);
                    Ok(Some(encode_error_response(
                        message_id,
                        LDAP_TAG_BIND_RESPONSE,
                        49, // invalidCredentials
                        "",
                        &format!("Bind failed: {}", e),
                    )?))
                }
            }
        }
        
        ProtocolOp::SearchRequest(search_req) => {
            debug!("Processing SEARCH request: base={}, filter={}", 
                   search_req.base_object, search_req.filter.to_ldap_string());
            
            let scope = scope_to_ldap3(search_req.scope);
            let attrs: Vec<&str> = search_req.attributes.iter().map(|s| s.as_str()).collect();
            let start = Instant::now();
            let search_result = handler.handle_search(
                &search_req.base_object,
                scope,
                &search_req.filter.to_ldap_string(),
                attrs,
                Some(session_key.as_slice()),
                session_conn.as_mut(),
            ).await;
            metrics.observe_duration("search", start.elapsed());
            match search_result {
                Ok((entries, result)) => {
                    metrics.inc_request("search");
                    let mut responses = Vec::new();
                    
                    // Send search result entries
                    for entry in entries {
                        let search_entry = SearchResultEntry {
                            object_name: entry.dn,
                            attributes: entry.attrs.iter().map(|(k, v)| {
                                Attribute {
                                    attr_type: k.clone(),
                                    attr_values: v.iter().map(|s| s.as_bytes().to_vec()).collect(),
                                }
                            }).collect(),
                        };
                        
                        let entry_msg = LdapMessage {
                            message_id,
                            protocol_op: ProtocolOp::SearchResultEntry(search_entry),
                            controls: None,
                        };
                        responses.push(encode_ldap_message(&entry_msg)?);
                    }
                    
                    // Send search result done
                    let done = SearchResultDone {
                        result_code: result.rc as i32,
                        matched_dn: result.matched.clone(),
                        diagnostic_message: result.text.clone(),
                    };
                    
                    let done_msg = LdapMessage {
                        message_id,
                        protocol_op: ProtocolOp::SearchResultDone(done),
                        controls: None,
                    };
                    responses.push(encode_ldap_message(&done_msg)?);
                    
                    // Combine all responses
                    let mut combined = Vec::new();
                    for resp in responses {
                        combined.extend_from_slice(&resp);
                    }
                    
                    Ok(Some(combined))
                }
                Err(e) => {
                    metrics.inc_error("search");
                    error!("Search failed: {}", e);
                    Ok(Some(encode_error_response(
                        message_id,
                        LDAP_TAG_SEARCH_RESULT_DONE,
                        80, // other
                        "",
                        &format!("Search failed: {}", e),
                    )?))
                }
            }
        }
        
        ProtocolOp::ModifyRequest(modify_req) => {
            debug!("Processing MODIFY request: {}", modify_req.object);
            
            use std::collections::HashSet;
            let modlist: Vec<ldap3::Mod<String>> = modify_req.changes.iter().map(|change| {
                let attr_vals: HashSet<String> = change.modification.attr_values.iter()
                    .map(|v| String::from_utf8_lossy(v).to_string())
                    .collect();
                
                match change.operation {
                    ModifyOperation::Add => ldap3::Mod::Add(
                        change.modification.attr_type.clone(),
                        attr_vals,
                    ),
                    ModifyOperation::Delete => ldap3::Mod::Delete(
                        change.modification.attr_type.clone(),
                        attr_vals,
                    ),
                    ModifyOperation::Replace => ldap3::Mod::Replace(
                        change.modification.attr_type.clone(),
                        attr_vals,
                    ),
                }
            }).collect();
            
            let start = Instant::now();
            let modify_result = handler.handle_modify(&modify_req.object, modlist, Some(session_key.as_slice()), session_conn.as_mut()).await;
            metrics.observe_duration("modify", start.elapsed());
            match modify_result {
                Ok(result) => {
                    metrics.inc_request("modify");
                    let response = ModifyResponse {
                        result_code: result.rc as i32,
                        matched_dn: result.matched.clone(),
                        diagnostic_message: result.text.clone(),
                    };
                    
                    let ldap_response = LdapMessage {
                        message_id,
                        protocol_op: ProtocolOp::ModifyResponse(response),
                        controls: None,
                    };

                    Ok(Some(encode_ldap_message(&ldap_response)?))
                }
                Err(e) => {
                    metrics.inc_error("modify");
                    error!("Modify failed: {}", e);
                    Ok(Some(encode_error_response(
                        message_id,
                        LDAP_TAG_MODIFY_RESPONSE,
                        80, // other
                        "",
                        &format!("Modify failed: {}", e),
                    )?))
                }
            }
        }
        
        ProtocolOp::AddRequest(add_req) => {
            debug!("Processing ADD request: {}", add_req.entry);
            
            let attrs: Vec<(String, Vec<String>)> = add_req.attributes.iter().map(|attr| {
                let vals: Vec<String> = attr.attr_values.iter()
                    .map(|v| String::from_utf8_lossy(v).to_string())
                    .collect();
                (attr.attr_type.clone(), vals)
            }).collect();
            
            let start = Instant::now();
            let add_result = handler.handle_add(&add_req.entry, attrs, Some(session_key.as_slice()), session_conn.as_mut()).await;
            metrics.observe_duration("add", start.elapsed());
            match add_result {
                Ok(result) => {
                    metrics.inc_request("add");
                    let response = AddResponse {
                        result_code: result.rc as i32,
                        matched_dn: result.matched.clone(),
                        diagnostic_message: result.text.clone(),
                    };
                    
                    let ldap_response = LdapMessage {
                        message_id,
                        protocol_op: ProtocolOp::AddResponse(response),
                        controls: None,
                    };

                    Ok(Some(encode_ldap_message(&ldap_response)?))
                }
                Err(e) => {
                    metrics.inc_error("add");
                    error!("Add failed: {}", e);
                    Ok(Some(encode_error_response(
                        message_id,
                        LDAP_TAG_ADD_RESPONSE,
                        80, // other
                        "",
                        &format!("Add failed: {}", e),
                    )?))
                }
            }
        }
        
        ProtocolOp::DelRequest(del_req) => {
            debug!("Processing DELETE request: {}", del_req.entry);
            
            let start = Instant::now();
            let del_result = handler.handle_delete(&del_req.entry, Some(session_key.as_slice()), session_conn.as_mut()).await;
            metrics.observe_duration("delete", start.elapsed());
            match del_result {
                Ok(result) => {
                    metrics.inc_request("delete");
                    let response = DelResponse {
                        result_code: result.rc as i32,
                        matched_dn: result.matched.clone(),
                        diagnostic_message: result.text.clone(),
                    };
                    
                    let ldap_response = LdapMessage {
                        message_id,
                        protocol_op: ProtocolOp::DelResponse(response),
                        controls: None,
                    };

                    Ok(Some(encode_ldap_message(&ldap_response)?))
                }
                Err(e) => {
                    metrics.inc_error("delete");
                    error!("Delete failed: {}", e);
                    Ok(Some(encode_error_response(
                        message_id,
                        LDAP_TAG_DEL_RESPONSE,
                        80, // other
                        "",
                        &format!("Delete failed: {}", e),
                    )?))
                }
            }
        }
        
        ProtocolOp::ModifyDNRequest(modify_dn_req) => {
            debug!("Processing MODIFYDN request: {} -> {}", modify_dn_req.entry, modify_dn_req.newrdn);
            
            let start = Instant::now();
            let modify_dn_result = handler.handle_modify_dn(
                &modify_dn_req.entry,
                &modify_dn_req.newrdn,
                modify_dn_req.delete_old_rdn,
                modify_dn_req.new_superior.as_deref(),
                Some(session_key.as_slice()),
                session_conn.as_mut(),
            ).await;
            metrics.observe_duration("modify_dn", start.elapsed());
            match modify_dn_result {
                Ok(result) => {
                    metrics.inc_request("modify_dn");
                    let response = ModifyDNResponse {
                        result_code: result.rc as i32,
                        matched_dn: result.matched.clone(),
                        diagnostic_message: result.text.clone(),
                    };
                    let ldap_response = LdapMessage {
                        message_id,
                        protocol_op: ProtocolOp::ModifyDNResponse(response),
                        controls: None,
                    };
                    Ok(Some(encode_ldap_message(&ldap_response)?))
                }
                Err(e) => {
                    metrics.inc_error("modify_dn");
                    error!("ModifyDN failed: {}", e);
                    Ok(Some(encode_error_response(
                        message_id,
                        LDAP_TAG_MODIFY_DN_RESPONSE,
                        80, // other
                        "",
                        &format!("ModifyDN failed: {}", e),
                    )?))
                }
            }
        }
        
        ProtocolOp::CompareRequest(compare_req) => {
            debug!("Processing COMPARE request: {} {}?", compare_req.entry, compare_req.attr);
            let value = String::from_utf8_lossy(&compare_req.assertion_value).to_string();
            let start = Instant::now();
            let compare_result = handler.handle_compare(
                &compare_req.entry,
                &compare_req.attr,
                &value,
                Some(session_key.as_slice()),
                session_conn.as_mut(),
            ).await;
            metrics.observe_duration("compare", start.elapsed());
            match compare_result {
                Ok(result) => {
                    metrics.inc_request("compare");
                    let response = CompareResponse {
                        result_code: result.rc as i32,
                        matched_dn: result.matched.clone(),
                        diagnostic_message: result.text.clone(),
                    };
                    let ldap_response = LdapMessage {
                        message_id,
                        protocol_op: ProtocolOp::CompareResponse(response),
                        controls: None,
                    };
                    Ok(Some(encode_ldap_message(&ldap_response)?))
                }
                Err(e) => {
                    metrics.inc_error("compare");
                    error!("Compare failed: {}", e);
                    Ok(Some(encode_error_response(
                        message_id,
                        LDAP_TAG_COMPARE_RESPONSE,
                        80, // other
                        "",
                        &format!("Compare failed: {}", e),
                    )?))
                }
            }
        }
        
        ProtocolOp::UnbindRequest => {
            debug!("Processing UNBIND request");
            *session_conn = None;
            Ok(None)
        }
        
        ProtocolOp::ExtendedRequest(ext_req) => {
            debug!("Processing EXTENDED request: {}", ext_req.request_name);
            
            if ext_req.request_name == "1.3.6.1.4.1.4203.1.11.3" {
                // WhoAmI extended operation
                let start = Instant::now();
                let whoami_result = handler.handle_extended_whoami(Some(session_key.as_slice()), session_conn.as_mut()).await;
                metrics.observe_duration("extended", start.elapsed());
                match whoami_result {
                    Ok(whoami_result) => {
                        metrics.inc_request("extended");
                        // WhoAmI response
                        let response = ExtendedResponse {
                            result_code: 0, // success
                            matched_dn: String::new(),
                            diagnostic_message: String::new(),
                            response_name: Some("1.3.6.1.4.1.4203.1.11.3".to_string()),
                            response_value: Some(whoami_result.as_bytes().to_vec()),
                        };
                        
                        let ldap_response = LdapMessage {
                            message_id,
                            protocol_op: ProtocolOp::ExtendedResponse(response),
                            controls: None,
                        };

                        Ok(Some(encode_ldap_message(&ldap_response)?))
                    }
                    Err(e) => {
                        metrics.inc_error("extended");
                        error!("Extended operation failed: {}", e);
                        Ok(Some(encode_error_response(
                            message_id,
                            LDAP_TAG_EXTENDED_RESPONSE,
                            80, // other
                            "",
                            &format!("Extended operation failed: {}", e),
                        )?))
                    }
                }
            } else {
                metrics.inc_error("extended");
                Ok(Some(encode_error_response(
                    message_id,
                    LDAP_TAG_EXTENDED_RESPONSE,
                    2, // protocolError
                    "",
                    "Unsupported extended operation",
                )?))
            }
        }
        
        _ => {
            metrics.inc_error("other");
            warn!("Unsupported operation type");
            Ok(Some(encode_error_response(
                message_id,
                0x65, // SearchResultDone as generic response
                2, // protocolError
                "",
                "Unsupported operation",
            )?))
        }
    }
}

fn encode_error_response(
    message_id: i32,
    response_tag: u8,
    result_code: i32,
    matched_dn: &str,
    diagnostic_message: &str,
) -> Result<Vec<u8>> {
    let mut writer = BerWriter::new();
    let seq_start = writer.start_sequence();
    writer.write_integer(message_id);
    writer.write_tag(response_tag);
    let len_pos = writer.write_length_placeholder();
    writer.write_enumerated(result_code as u8);
    writer.write_string(matched_dn);
    writer.write_string(diagnostic_message);
    writer.patch_implicit_sequence_length(len_pos);
    writer.end_sequence(seq_start);
    Ok(writer.into_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_listen_url_ldap() {
        let addr = parse_listen_url("ldap://127.0.0.1:1389").unwrap();
        assert_eq!(addr.port(), 1389);
        assert_eq!(addr.ip().to_string(), "127.0.0.1");
    }

    #[test]
    fn test_parse_listen_url_ldaps() {
        let addr = parse_listen_url("ldaps://0.0.0.0:636").unwrap();
        assert_eq!(addr.port(), 636);
        assert_eq!(addr.ip().to_string(), "0.0.0.0");
    }

    #[test]
    fn test_parse_listen_url_port_only() {
        let addr = parse_listen_url("ldap://:1389").unwrap();
        assert_eq!(addr.port(), 1389);
        assert_eq!(addr.ip().to_string(), "0.0.0.0");
    }

    #[test]
    fn test_parse_listen_url_with_slashes() {
        let addr = parse_listen_url("ldap:///127.0.0.1:1389").unwrap();
        assert_eq!(addr.port(), 1389);
    }

    #[test]
    fn test_parse_listen_url_invalid_scheme() {
        assert!(parse_listen_url("http://127.0.0.1:1389").is_err());
        assert!(parse_listen_url("invalid://127.0.0.1:1389").is_err());
    }

    #[test]
    fn test_parse_listen_url_invalid_port() {
        assert!(parse_listen_url("ldap://:99999").is_err());
        assert!(parse_listen_url("ldap://:abc").is_err());
    }

    #[test]
    fn test_parse_listen_url_invalid_address() {
        assert!(parse_listen_url("ldap://invalid:address").is_err());
    }

    #[test]
    fn test_encode_error_response() {
        let response = encode_error_response(
            1,
            LDAP_TAG_BIND_RESPONSE,
            49,
            "cn=test",
            "Invalid credentials",
        ).unwrap();
        assert!(!response.is_empty());
    }

    #[test]
    fn test_encode_error_response_search() {
        let response = encode_error_response(
            2,
            LDAP_TAG_SEARCH_RESULT_DONE,
            80,
            "",
            "Search failed",
        ).unwrap();
        assert!(!response.is_empty());
    }

    #[test]
    fn test_encode_error_response_empty_strings() {
        let response = encode_error_response(
            3,
            LDAP_TAG_MODIFY_RESPONSE,
            0,
            "",
            "",
        ).unwrap();
        assert!(!response.is_empty());
    }
}

