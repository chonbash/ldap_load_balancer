//! Метрики для мониторинга в формате Prometheus (RED: Rate, Errors, Duration).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use anyhow::{Context, Result};
use tracing::{error, info};
use serde::Serialize;

/// Верхние границы корзин гистограммы длительности (в секундах). +Inf даётся отдельно как count.
const DURATION_BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Гистограмма для одной операции: корзины + счётчик + сумма (в микросекундах).
#[derive(Debug, Default)]
struct DurationHistogram {
    buckets: [AtomicU64; 11],
    count: AtomicU64,
    sum_micros: AtomicU64,
}

impl DurationHistogram {
    fn observe(&self, duration: Duration) {
        let micros = duration.as_micros().min(u64::MAX as u128) as u64;
        let secs = duration.as_secs_f64();
        // Инкрементируем только одну корзину: первую, для которой secs <= le (некумулятивное хранение).
        if let Some(i) = DURATION_BUCKETS.iter().position(|&le| secs <= le) {
            self.buckets[i].fetch_add(1, Ordering::Relaxed);
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_micros.fetch_add(micros, Ordering::Relaxed);
    }
}

/// Счётчики метрик (thread-safe, lock-free).
#[derive(Debug)]
pub struct Metrics {
    /// Всего принятых клиентских подключений.
    pub connections_total: AtomicU64,
    /// Запросы по типам операций (успешные).
    pub requests_bind: AtomicU64,
    pub requests_search: AtomicU64,
    pub requests_add: AtomicU64,
    pub requests_modify: AtomicU64,
    pub requests_delete: AtomicU64,
    pub requests_modify_dn: AtomicU64,
    pub requests_compare: AtomicU64,
    pub requests_extended: AtomicU64,
    /// Ошибки парсинга LDAP-сообщений (невалидный BER / не SEQUENCE в начале).
    pub parse_errors: AtomicU64,
    /// Ошибки по типам операций.
    pub errors_bind: AtomicU64,
    pub errors_search: AtomicU64,
    pub errors_add: AtomicU64,
    pub errors_modify: AtomicU64,
    pub errors_delete: AtomicU64,
    pub errors_modify_dn: AtomicU64,
    pub errors_compare: AtomicU64,
    pub errors_extended: AtomicU64,
    pub errors_other: AtomicU64,
    /// Per-backend request counts: (uri, op) -> count. Used for ldap_lb_backend_requests_total.
    backend_requests: dashmap::DashMap<(String, String), AtomicU64>,
    /// Duration (RED): гистограммы времени обработки по типу операции.
    duration_bind: DurationHistogram,
    duration_search: DurationHistogram,
    duration_add: DurationHistogram,
    duration_modify: DurationHistogram,
    duration_delete: DurationHistogram,
    duration_modify_dn: DurationHistogram,
    duration_compare: DurationHistogram,
    duration_extended: DurationHistogram,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            connections_total: AtomicU64::new(0),
            parse_errors: AtomicU64::new(0),
            requests_bind: AtomicU64::new(0),
            requests_search: AtomicU64::new(0),
            requests_add: AtomicU64::new(0),
            requests_modify: AtomicU64::new(0),
            requests_delete: AtomicU64::new(0),
            requests_modify_dn: AtomicU64::new(0),
            requests_compare: AtomicU64::new(0),
            requests_extended: AtomicU64::new(0),
            errors_bind: AtomicU64::new(0),
            errors_search: AtomicU64::new(0),
            errors_add: AtomicU64::new(0),
            errors_modify: AtomicU64::new(0),
            errors_delete: AtomicU64::new(0),
            errors_modify_dn: AtomicU64::new(0),
            errors_compare: AtomicU64::new(0),
            errors_extended: AtomicU64::new(0),
            errors_other: AtomicU64::new(0),
            backend_requests: dashmap::DashMap::new(),
            duration_bind: DurationHistogram::default(),
            duration_search: DurationHistogram::default(),
            duration_add: DurationHistogram::default(),
            duration_modify: DurationHistogram::default(),
            duration_delete: DurationHistogram::default(),
            duration_modify_dn: DurationHistogram::default(),
            duration_compare: DurationHistogram::default(),
            duration_extended: DurationHistogram::default(),
        }
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Увеличивает счётчик подключений на 1.
    #[inline]
    pub fn inc_connections(&self) {
        self.connections_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Увеличивает счётчик успешных запросов по типу операции.
    #[inline]
    pub fn inc_request(&self, op: &str) {
        match op {
            "bind" => self.requests_bind.fetch_add(1, Ordering::Relaxed),
            "search" => self.requests_search.fetch_add(1, Ordering::Relaxed),
            "add" => self.requests_add.fetch_add(1, Ordering::Relaxed),
            "modify" => self.requests_modify.fetch_add(1, Ordering::Relaxed),
            "delete" => self.requests_delete.fetch_add(1, Ordering::Relaxed),
            "modify_dn" => self.requests_modify_dn.fetch_add(1, Ordering::Relaxed),
            "compare" => self.requests_compare.fetch_add(1, Ordering::Relaxed),
            "extended" => self.requests_extended.fetch_add(1, Ordering::Relaxed),
            _ => return,
        };
    }

    /// Учитывает длительность запроса (RED: Duration). Вызывать после успешной или неуспешной обработки.
    #[inline]
    pub fn observe_duration(&self, op: &str, duration: Duration) {
        match op {
            "bind" => self.duration_bind.observe(duration),
            "search" => self.duration_search.observe(duration),
            "add" => self.duration_add.observe(duration),
            "modify" => self.duration_modify.observe(duration),
            "delete" => self.duration_delete.observe(duration),
            "modify_dn" => self.duration_modify_dn.observe(duration),
            "compare" => self.duration_compare.observe(duration),
            "extended" => self.duration_extended.observe(duration),
            _ => {}
        }
    }

    /// Увеличивает счётчик ошибок парсинга (ожидался SEQUENCE, пришёл другой тег и т.д.).
    #[inline]
    pub fn inc_parse_error(&self) {
        self.parse_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Увеличивает счётчик ошибок по типу операции.
    /// Increment per-backend request count (proxy mode). Call on successful request.
    #[inline]
    pub fn inc_backend_request(&self, uri: &str, op: &str) {
        let key = (uri.to_string(), op.to_string());
        self.backend_requests
            .entry(key)
            .or_insert_with(AtomicU64::default)
            .fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_error(&self, op: &str) {
        match op {
            "bind" => self.errors_bind.fetch_add(1, Ordering::Relaxed),
            "search" => self.errors_search.fetch_add(1, Ordering::Relaxed),
            "add" => self.errors_add.fetch_add(1, Ordering::Relaxed),
            "modify" => self.errors_modify.fetch_add(1, Ordering::Relaxed),
            "delete" => self.errors_delete.fetch_add(1, Ordering::Relaxed),
            "modify_dn" => self.errors_modify_dn.fetch_add(1, Ordering::Relaxed),
            "compare" => self.errors_compare.fetch_add(1, Ordering::Relaxed),
            "extended" => self.errors_extended.fetch_add(1, Ordering::Relaxed),
            "other" => self.errors_other.fetch_add(1, Ordering::Relaxed),
            _ => return,
        };
    }

    /// Рендер метрик в текстовом формате Prometheus (exposition format).
    /// `backend_states`: список (uri, Some(is_up)) или (uri, None) когда health check отключён (unknown = -1).
    pub fn render(&self, backend_servers: usize, backend_states: &[(String, Option<bool>)]) -> String {
        let mut out = String::new();
        let c = self.connections_total.load(Ordering::Relaxed);
        out.push_str("# HELP ldap_lb_connections_total Total number of client connections accepted.\n");
        out.push_str("# TYPE ldap_lb_connections_total counter\n");
        out.push_str(&format!("ldap_lb_connections_total {}\n", c));

        let pe = self.parse_errors.load(Ordering::Relaxed);
        out.push_str("# HELP ldap_lb_parse_errors_total Total number of LDAP message parse errors (invalid BER / wrong tag).\n");
        out.push_str("# TYPE ldap_lb_parse_errors_total counter\n");
        out.push_str(&format!("ldap_lb_parse_errors_total {}\n", pe));

        out.push_str("# HELP ldap_lb_requests_total Total LDAP requests by operation (success).\n");
        out.push_str("# TYPE ldap_lb_requests_total counter\n");
        for (op, val) in [
            ("bind", self.requests_bind.load(Ordering::Relaxed)),
            ("search", self.requests_search.load(Ordering::Relaxed)),
            ("add", self.requests_add.load(Ordering::Relaxed)),
            ("modify", self.requests_modify.load(Ordering::Relaxed)),
            ("delete", self.requests_delete.load(Ordering::Relaxed)),
            ("modify_dn", self.requests_modify_dn.load(Ordering::Relaxed)),
            ("compare", self.requests_compare.load(Ordering::Relaxed)),
            ("extended", self.requests_extended.load(Ordering::Relaxed)),
        ] {
            out.push_str(&format!("ldap_lb_requests_total{{op=\"{}\"}} {}\n", op, val));
        }

        out.push_str("# HELP ldap_lb_errors_total Total errors by operation.\n");
        out.push_str("# TYPE ldap_lb_errors_total counter\n");
        for (op, val) in [
            ("bind", self.errors_bind.load(Ordering::Relaxed)),
            ("search", self.errors_search.load(Ordering::Relaxed)),
            ("add", self.errors_add.load(Ordering::Relaxed)),
            ("modify", self.errors_modify.load(Ordering::Relaxed)),
            ("delete", self.errors_delete.load(Ordering::Relaxed)),
            ("modify_dn", self.errors_modify_dn.load(Ordering::Relaxed)),
            ("compare", self.errors_compare.load(Ordering::Relaxed)),
            ("extended", self.errors_extended.load(Ordering::Relaxed)),
            ("other", self.errors_other.load(Ordering::Relaxed)),
        ] {
            out.push_str(&format!("ldap_lb_errors_total{{op=\"{}\"}} {}\n", op, val));
        }

        out.push_str("# HELP ldap_lb_backend_servers Number of configured backend servers.\n");
        out.push_str("# TYPE ldap_lb_backend_servers gauge\n");
        out.push_str(&format!("ldap_lb_backend_servers {}\n", backend_servers));

        out.push_str("# HELP ldap_lb_backend_up Backend node state: 1 = up (healthy), 0 = down, -1 = unknown (health check disabled).\n");
        out.push_str("# TYPE ldap_lb_backend_up gauge\n");
        for (uri, is_up) in backend_states {
            let val = match is_up {
                Some(true) => 1,
                Some(false) => 0,
                None => -1,
            };
            let escaped = uri.replace('\\', "\\\\").replace('"', "\\\"");
            out.push_str(&format!("ldap_lb_backend_up{{uri=\"{}\"}} {}\n", escaped, val));
        }

        out.push_str("# HELP ldap_lb_backend_requests_total Total requests forwarded to each backend by operation (proxy mode).\n");
        out.push_str("# TYPE ldap_lb_backend_requests_total counter\n");
        for entry in self.backend_requests.iter() {
            let ((uri, op), count) = (entry.key(), entry.value().load(Ordering::Relaxed));
            let u = uri.replace('\\', "\\\\").replace('"', "\\\"");
            out.push_str(&format!("ldap_lb_backend_requests_total{{uri=\"{}\",op=\"{}\"}} {}\n", u, op, count));
        }

        // RED: Duration — гистограмма длительности запросов по операциям
        out.push_str("# HELP ldap_lb_request_duration_seconds Request duration in seconds by operation.\n");
        out.push_str("# TYPE ldap_lb_request_duration_seconds histogram\n");
        for (op, hist) in [
            ("bind", &self.duration_bind),
            ("search", &self.duration_search),
            ("add", &self.duration_add),
            ("modify", &self.duration_modify),
            ("delete", &self.duration_delete),
            ("modify_dn", &self.duration_modify_dn),
            ("compare", &self.duration_compare),
            ("extended", &self.duration_extended),
        ] {
            let count = hist.count.load(Ordering::Relaxed);
            let mut cum = 0u64;
            for (i, &le) in DURATION_BUCKETS.iter().enumerate() {
                cum += hist.buckets[i].load(Ordering::Relaxed);
                out.push_str(&format!(
                    "ldap_lb_request_duration_seconds_bucket{{op=\"{}\",le=\"{}\"}} {}\n",
                    op, le, cum
                ));
            }
            out.push_str(&format!(
                "ldap_lb_request_duration_seconds_bucket{{op=\"{}\",le=\"+Inf\"}} {}\n",
                op, count
            ));
            let sum_secs = hist.sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0;
            out.push_str(&format!(
                "ldap_lb_request_duration_seconds_sum{{op=\"{}\"}} {}\n",
                op, sum_secs
            ));
            out.push_str(&format!(
                "ldap_lb_request_duration_seconds_count{{op=\"{}\"}} {}\n",
                op, count
            ));
        }

        out
    }
}

/// Тело ответа GET /ready: список бэкендов и их состояние.
#[derive(Serialize)]
struct ReadyBody {
    ready: bool,
    backends: Vec<BackendState>,
}

#[derive(Serialize)]
struct BackendState {
    uri: String,
    /// true = up, false = down, null = unknown (health check disabled)
    up: Option<bool>,
}

/// Извлекает путь из первой строки HTTP-запроса (например "GET /health HTTP/1.1" -> "/health").
fn request_path(first_line: &str) -> &str {
    let line = first_line.trim();
    let mut parts = line.split_ascii_whitespace();
    let _method = parts.next();
    let path = parts.next().unwrap_or("");
    if path.starts_with('/') {
        path
    } else {
        ""
    }
}

/// Запускает HTTP-сервер для эндпоинтов GET /metrics, GET /health, GET /ready.
/// - /health (liveness): 200 если процесс жив.
/// - /ready (readiness): 200 если есть хотя бы один здоровый backend, иначе 503.
/// `backend_info` вызывается при запросах /metrics и /ready: (число бэкендов, список (uri, Option<is_up>); None = unknown when health disabled).
pub async fn run_metrics_server(
    addr: &str,
    metrics: Arc<Metrics>,
    backend_info: Arc<dyn Fn() -> (usize, Vec<(String, Option<bool>)>) + Send + Sync>,
) -> Result<()> {
    let socket_addr: SocketAddr = addr
        .parse()
        .with_context(|| format!("Invalid metrics listen address: {}", addr))?;

    let listener = TcpListener::bind(&socket_addr)
        .await
        .with_context(|| format!("Failed to bind metrics server to {}", socket_addr))?;

    info!("Metrics server listening on http://{} (GET /metrics, /health, /ready)", socket_addr);

    loop {
        let (mut stream, _peer) = match listener.accept().await {
            Ok(accept) => accept,
            Err(e) => {
                error!("Metrics accept error: {}", e);
                continue;
            }
        };

        let metrics = Arc::clone(&metrics);
        let backend_info = Arc::clone(&backend_info);

        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            let mut total = 0usize;
            loop {
                match stream.read(&mut buf[total..]).await {
                    Ok(0) => break,
                    Ok(n) => {
                        total += n;
                        if total >= 4 && buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                        if total >= buf.len() {
                            break;
                        }
                    }
                    Err(_) => return,
                }
            }

            let request = String::from_utf8_lossy(&buf[..total]);
            let path = request
                .lines()
                .next()
                .map(request_path)
                .unwrap_or("");

            let (status, body, content_type) = match path {
                "/health" => ("200 OK", "ok".to_string(), "text/plain; charset=utf-8"),
                "/ready" => {
                    let (_count, states) = backend_info();
                    let ready = states.iter().any(|(_, is_up)| *is_up == Some(true))
                        || (states.iter().all(|(_, u)| u.is_none()) && !states.is_empty());
                    let backends: Vec<BackendState> = states
                        .into_iter()
                        .map(|(uri, up)| BackendState { uri, up })
                        .collect();
                    let body_json = serde_json::to_string(&ReadyBody {
                        ready,
                        backends,
                    }).unwrap_or_else(|_| r#"{"ready":false,"backends":[],"error":"serialize"}"#.to_string());
                    let status = if ready { "200 OK" } else { "503 Service Unavailable" };
                    (status, body_json, "application/json")
                }
                "/metrics" => {
                    let (count, states) = backend_info();
                    ("200 OK", metrics.render(count, &states), "text/plain; charset=utf-8")
                }
                _ => ("404 Not Found", "Not found. Supported: GET /metrics, GET /health, GET /ready.\n".to_string(), "text/plain; charset=utf-8"),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: {}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                status,
                content_type,
                body.len(),
                body
            );

            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{request_path, Metrics};

    #[test]
    fn test_request_path_health() {
        assert_eq!(request_path("GET /health HTTP/1.1"), "/health");
    }

    #[test]
    fn test_request_path_ready() {
        assert_eq!(request_path("GET /ready HTTP/1.0"), "/ready");
    }

    #[test]
    fn test_request_path_metrics() {
        assert_eq!(request_path("GET /metrics HTTP/1.1"), "/metrics");
    }

    #[test]
    fn test_request_path_empty() {
        assert_eq!(request_path(""), "");
        assert_eq!(request_path("GET  HTTP/1.1"), "");
    }

    #[test]
    fn test_backend_requests_metric() {
        let m = Metrics::default();
        m.inc_backend_request("ldap://ldap1:389", "search");
        m.inc_backend_request("ldap://ldap1:389", "search");
        m.inc_backend_request("ldap://ldap2:389", "bind");
        let out = m.render(2, &[
            ("ldap://ldap1:389".to_string(), Some(true)),
            ("ldap://ldap2:389".to_string(), Some(true)),
        ]);
        assert!(out.contains("ldap_lb_backend_requests_total"));
        assert!(out.contains("ldap://ldap1:389"));
        assert!(out.contains("ldap://ldap2:389"));
        assert!(out.contains("op=\"search\""));
        assert!(out.contains("op=\"bind\""));
    }
}
