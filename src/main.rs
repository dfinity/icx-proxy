use axum::{handler::Handler, routing::get, Extension, Router};
use clap::{crate_authors, crate_version, Parser};
use futures::{future::OptionFuture, try_join, FutureExt, StreamExt};
use http_body::{LengthLimitError, Limited};
use hyper::{
    body,
    http::{header::CONTENT_TYPE, uri::Parts},
    service::{make_service_fn, service_fn},
    Body, Client, Request, Response, Server, StatusCode, Uri,
};
use ic_agent::{
    agent::http_transport::{reqwest, ReqwestHttpReplicaV2Transport},
    agent_error::HttpErrorPayload,
    Agent, AgentError,
};
use ic_utils::{
    call::AsyncCall,
    call::SyncCall,
    interfaces::http_request::{
        HeaderField, HttpRequestCanister, HttpRequestStreamingCallbackAny, HttpResponse,
        StreamingCallbackHttpResponse, StreamingStrategy, Token,
    },
};
use opentelemetry::{global, sdk::Resource, KeyValue};
use opentelemetry_prometheus::PrometheusExporter;
use prometheus::{Encoder, TextEncoder};
use slog::Drain;
use std::{
    convert::Infallible,
    error::Error,
    fs::File,
    io::{Cursor, Read},
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    str::FromStr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

mod canister_id;
mod config;
mod headers;
mod logging;
mod metrics;
mod validate;

use crate::{
    config::dns_canister_config::DnsCanisterConfig,
    headers::{extract_headers_data, HeadersData},
    metrics::{MetricParams, WithMetrics},
    validate::{Validate, Validator},
};

type HttpResponseAny = HttpResponse<Token, HttpRequestStreamingCallbackAny>;

// Limit the total number of calls to an HTTP Request loop to 1000 for now.
const MAX_HTTP_REQUEST_STREAM_CALLBACK_CALL_COUNT: usize = 1000;

// Limit the number of Stream Callbacks buffered
const STREAM_CALLBACK_BUFFFER: usize = 2;

// The maximum length of a body we should log as tracing.
const MAX_LOG_BODY_SIZE: usize = 100;

const KB: usize = 1024;
const MB: usize = 1024 * KB;

const REQUEST_BODY_SIZE_LIMIT: usize = 10 * MB;
const RESPONSE_BODY_SIZE_LIMIT: usize = 10 * MB;

/// Resolve overrides for [`reqwest::ClientBuilder::resolve()`]
/// `ic0.app=[::1]:9090`
pub(crate) struct OptResolve {
    domain: String,
    addr: SocketAddr,
}

impl FromStr for OptResolve {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, anyhow::Error> {
        let (domain, addr) = s
            .split_once('=')
            .ok_or_else(|| anyhow::Error::msg("missing '='"))?;
        Ok(OptResolve {
            domain: domain.into(),
            addr: addr.parse()?,
        })
    }
}

#[derive(Parser)]
#[clap(
    version = crate_version!(),
    author = crate_authors!(),
    propagate_version = true,
)]
pub(crate) struct Opts {
    /// Verbose level. By default, INFO will be used. Add a single `-v` to upgrade to
    /// DEBUG, and another `-v` to upgrade to TRACE.
    #[clap(long, short('v'), parse(from_occurrences))]
    verbose: u64,

    /// Quiet level. The opposite of verbose. A single `-q` will drop the logging to
    /// WARN only, then another one to ERR, and finally another one for FATAL. Another
    /// `-q` will silence ALL logs.
    #[clap(long, short('q'), parse(from_occurrences))]
    quiet: u64,

    /// Mode to use the logging. "stderr" will output logs in STDERR, "file" will output
    /// logs in a file, and "tee" will do both.
    #[clap(long("log"), default_value("stderr"), possible_values(&["stderr", "tee", "file"]))]
    logmode: String,

    /// File to output the log to, when using logmode=tee or logmode=file.
    #[clap(long)]
    logfile: Option<PathBuf>,

    /// The address to bind to.
    #[clap(long, default_value = "127.0.0.1:3000")]
    address: SocketAddr,

    /// A replica to use as backend. Locally, this should be a local instance or the
    /// boundary node. Multiple replicas can be passed and they'll be used round-robin.
    #[clap(long, default_value = "http://localhost:8000/")]
    replica: Vec<String>,

    /// Override DNS resolution for specific replica domains to particular IP addresses.
    /// Examples: ic0.app=[::1]:9090
    #[clap(long, value_name("DOMAIN=IP_PORT"))]
    replica_resolve: Vec<OptResolve>,

    /// An address to forward any requests from /_/
    #[clap(long)]
    proxy: Option<String>,

    /// Whether or not this is run in a debug context (e.g. errors returned in responses
    /// should show full stack and error details).
    #[clap(long)]
    debug: bool,

    /// Whether or not to fetch the root key from the replica back end. Do not use this when
    /// talking to the Internet Computer blockchain mainnet as it is unsecure.
    #[clap(long)]
    fetch_root_key: bool,

    /// The list of custom root HTTPS certificates to use to talk to the replica. This can be used
    /// to connect to an IC that has a self-signed certificate, for example. Do not use this when
    /// talking to the Internet Computer blockchain mainnet as it is unsecure.
    #[clap(long)]
    ssl_root_certificate: Vec<PathBuf>,

    /// Allows HTTPS connection to replicas with invalid HTTPS certificates. This can be used to
    /// connect to an IC that has a self-signed certificate, for example. Do not use this when
    /// talking to the Internet Computer blockchain mainnet as it is *VERY* unsecure.
    #[clap(long)]
    danger_accept_invalid_ssl: bool,

    /// A map of domain names to canister IDs.
    /// Format: domain.name:canister-id
    #[clap(long)]
    dns_alias: Vec<String>,

    /// A list of domain name suffixes.  If found, the next (to the left) subdomain
    /// is used as the Principal, if it parses as a Principal.
    #[clap(long, default_value = "localhost")]
    dns_suffix: Vec<String>,

    /// Whether or not to ignore `canisterId=` when locating the canister.
    #[clap(long)]
    ignore_url_canister_param: bool,

    /// Address to expose Prometheus metrics on
    /// Examples: 127.0.0.1:9090, [::1]:9090
    #[clap(long)]
    metrics_addr: Option<SocketAddr>,
}

async fn forward_request(
    request: Request<Body>,
    agent: Arc<Agent>,
    resolver: &dyn canister_id::Resolver<Body>,
    validator: &dyn Validate,
    logger: slog::Logger,
) -> Result<Response<Body>, Box<dyn Error>> {
    let canister_id = match resolver.resolve(&request) {
        None => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("Could not find a canister id to forward to.".into())
                .unwrap())
        }
        Some(x) => x,
    };

    slog::trace!(
        logger,
        "<< {} {} {:?}",
        request.method(),
        request.uri(),
        &request.version()
    );

    let (parts, body) = request.into_parts();
    let method = parts.method;
    let uri = parts.uri.to_string();
    let headers = parts
        .headers
        .iter()
        .filter_map(|(name, value)| {
            Some(HeaderField(
                name.as_str().into(),
                value.to_str().ok()?.into(),
            ))
        })
        .inspect(|HeaderField(name, value)| {
            slog::trace!(logger, "<< {}: {}", name, value);
        })
        .collect::<Vec<_>>();

    // Limit request body size
    let body = Limited::new(body, REQUEST_BODY_SIZE_LIMIT);
    let entire_body = match hyper::body::to_bytes(body).await {
        Ok(data) => data,
        Err(err) => {
            if err.downcast_ref::<LengthLimitError>().is_some() {
                return Ok(Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .body(Body::from("Request size exceeds limit"))?);
            }
            return Err(err);
        }
    }
    .to_vec();

    slog::trace!(logger, "<<");
    if logger.is_trace_enabled() {
        let body = String::from_utf8_lossy(
            &entire_body[0..usize::min(entire_body.len(), MAX_LOG_BODY_SIZE)],
        );
        slog::trace!(
            logger,
            "<< \"{}\"{}",
            &body.escape_default(),
            if body.len() > MAX_LOG_BODY_SIZE {
                format!("... {} bytes total", body.len())
            } else {
                String::new()
            }
        );
    }

    let canister = HttpRequestCanister::create(agent.as_ref(), canister_id);
    let query_result = canister
        .http_request_custom(
            method.as_str(),
            uri.as_str(),
            headers.iter().cloned(),
            &entire_body,
        )
        .call()
        .await;

    fn handle_result(
        result: Result<(HttpResponseAny,), AgentError>,
    ) -> Result<HttpResponseAny, Result<Response<Body>, Box<dyn Error>>> {
        // If the result is a Replica error, returns the 500 code and message. There is no information
        // leak here because a user could use `dfx` to get the same reply.
        match result {
            Ok((http_response,)) => Ok(http_response),

            Err(AgentError::ReplicaError {
                reject_code,
                reject_message,
            }) => Err(Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(format!(r#"Replica Error ({}): "{}""#, reject_code, reject_message).into())
                .unwrap())),

            Err(AgentError::HttpError(HttpErrorPayload {
                status: 451,
                content_type,
                content,
            })) => Err(Ok(content_type
                .into_iter()
                .fold(Response::builder(), |r, c| r.header(CONTENT_TYPE, c))
                .status(451)
                .body(content.into())
                .unwrap())),

            Err(AgentError::ResponseSizeExceededLimit()) => Err(Ok(Response::builder()
                .status(StatusCode::INSUFFICIENT_STORAGE)
                .body("Response size exceeds limit".into())
                .unwrap())),

            Err(e) => Err(Err(e.into())),
        }
    }

    let http_response = match handle_result(query_result) {
        Ok(http_response) => http_response,
        Err(response_or_error) => return response_or_error,
    };

    let http_response = if http_response.upgrade == Some(true) {
        let waiter = garcon::Delay::builder()
            .throttle(std::time::Duration::from_millis(500))
            .timeout(std::time::Duration::from_secs(15))
            .build();
        let update_result = canister
            .http_request_update_custom(
                method.as_str(),
                uri.as_str(),
                headers.iter().cloned(),
                &entire_body,
            )
            .call_and_wait(waiter)
            .await;
        let http_response = match handle_result(update_result) {
            Ok(http_response) => http_response,
            Err(response_or_error) => return response_or_error,
        };
        http_response
    } else {
        http_response
    };

    let mut builder = Response::builder().status(StatusCode::from_u16(http_response.status_code)?);
    for HeaderField(name, value) in &http_response.headers {
        builder = builder.header(name.as_ref(), value.as_ref());
    }

    let headers_data = extract_headers_data(&http_response.headers, &logger);
    let body = if logger.is_trace_enabled() {
        Some(http_response.body.clone())
    } else {
        None
    };
    let is_streaming = http_response.streaming_strategy.is_some();
    let response = if let Some(streaming_strategy) = http_response.streaming_strategy {
        let body = http_response.body;
        let body = futures::stream::once(async move { Ok(body) });
        let body = match streaming_strategy {
            StreamingStrategy::Callback(callback) => body::Body::wrap_stream(
                body.chain(futures::stream::try_unfold(
                    (
                        logger.clone(),
                        agent,
                        callback.callback.0,
                        Some(callback.token),
                    ),
                    move |(logger, agent, callback, callback_token)| async move {
                        let callback_token = match callback_token {
                            Some(callback_token) => callback_token,
                            None => return Ok(None),
                        };

                        let canister = HttpRequestCanister::create(&agent, callback.principal);
                        match canister
                            .http_request_stream_callback(&callback.method, callback_token)
                            .call()
                            .await
                        {
                            Ok((StreamingCallbackHttpResponse { body, token },)) => {
                                Ok(Some((body, (logger, agent, callback, token))))
                            }
                            Err(e) => {
                                slog::warn!(logger, "Error happened during streaming: {}", e);
                                Err(e)
                            }
                        }
                    },
                ))
                .take(MAX_HTTP_REQUEST_STREAM_CALLBACK_CALL_COUNT)
                .map(|x| async move { x })
                .buffered(STREAM_CALLBACK_BUFFFER),
            ),
        };

        builder.body(body)?
    } else {
        let body_valid = validator.validate(
            &headers_data,
            &canister_id,
            &agent,
            &parts.uri,
            &http_response.body,
            logger.clone(),
        );
        if body_valid.is_err() {
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(body_valid.unwrap_err().into())
                .unwrap());
        }
        builder.body(http_response.body.into())?
    };

    if logger.is_trace_enabled() {
        slog::trace!(
            logger,
            ">> {:?} {} {}",
            &response.version(),
            response.status().as_u16(),
            response.status().to_string()
        );

        for (name, value) in response.headers() {
            let value = String::from_utf8_lossy(value.as_bytes());
            slog::trace!(logger, ">> {}: {}", name, value);
        }

        let body = body.unwrap_or_else(|| b"... streaming ...".to_vec());

        slog::trace!(logger, ">>");
        slog::trace!(
            logger,
            ">> \"{}\"{}",
            String::from_utf8_lossy(&body[..usize::min(MAX_LOG_BODY_SIZE, body.len())])
                .escape_default(),
            if is_streaming {
                "... streaming".to_string()
            } else if body.len() > MAX_LOG_BODY_SIZE {
                format!("... {} bytes total", body.len())
            } else {
                String::new()
            }
        );
    }

    Ok(response)
}

fn is_hop_header(name: &str) -> bool {
    name.to_ascii_lowercase() == "connection"
        || name.to_ascii_lowercase() == "keep-alive"
        || name.to_ascii_lowercase() == "proxy-authenticate"
        || name.to_ascii_lowercase() == "proxy-authorization"
        || name.to_ascii_lowercase() == "te"
        || name.to_ascii_lowercase() == "trailers"
        || name.to_ascii_lowercase() == "transfer-encoding"
        || name.to_ascii_lowercase() == "upgrade"
}

/// Returns a clone of the headers without the [hop-by-hop headers].
///
/// [hop-by-hop headers]: http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
fn remove_hop_headers(
    headers: &hyper::header::HeaderMap<hyper::header::HeaderValue>,
) -> hyper::header::HeaderMap<hyper::header::HeaderValue> {
    let mut result = hyper::HeaderMap::new();
    for (k, v) in headers.iter() {
        if !is_hop_header(k.as_str()) {
            result.insert(k.clone(), v.clone());
        }
    }
    result
}

fn forward_uri<B>(forward_url: &str, req: &Request<B>) -> Result<Uri, Box<dyn Error>> {
    let uri = Uri::from_str(forward_url)?;
    let mut parts = Parts::from(uri);
    parts.path_and_query = req.uri().path_and_query().cloned();

    Ok(Uri::from_parts(parts)?)
}

fn create_proxied_request<B>(
    client_ip: &IpAddr,
    forward_url: &str,
    mut request: Request<B>,
) -> Result<Request<B>, Box<dyn Error>> {
    *request.headers_mut() = remove_hop_headers(request.headers());
    *request.uri_mut() = forward_uri(forward_url, &request)?;

    let x_forwarded_for_header_name = "x-forwarded-for";

    // Add forwarding information in the headers
    match request.headers_mut().entry(x_forwarded_for_header_name) {
        hyper::header::Entry::Vacant(entry) => {
            entry.insert(client_ip.to_string().parse()?);
        }

        hyper::header::Entry::Occupied(mut entry) => {
            let addr = format!("{}, {}", entry.get().to_str()?, client_ip);
            entry.insert(addr.parse()?);
        }
    }

    Ok(request)
}

async fn forward_api(
    ip_addr: &IpAddr,
    request: Request<Body>,
    replica_url: &str,
) -> Result<Response<Body>, Box<dyn Error>> {
    let proxied_request = create_proxied_request(ip_addr, replica_url, request)?;

    let client = Client::builder().build(hyper_tls::HttpsConnector::new());
    let response = client.request(proxied_request).await?;
    Ok(response)
}

fn not_found() -> Result<Response<Body>, Box<dyn Error>> {
    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body("Not found".into())?)
}

fn unable_to_fetch_root_key() -> Result<Response<Body>, Box<dyn Error>> {
    Ok(Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body("Unable to fetch root key".into())?)
}

struct HandleRequest {
    ip_addr: IpAddr,
    request: Request<Body>,
    replica_url: String,
    client: reqwest::Client,
    proxy_url: Option<String>,
    resolver: Arc<dyn canister_id::Resolver<Body>>,
    validator: Arc<dyn Validate>,
    logger: slog::Logger,
    fetch_root_key: bool,
    debug: bool,
}

async fn handle_request(
    HandleRequest {
        ip_addr,
        request,
        replica_url,
        client,
        proxy_url,
        resolver,
        validator,
        logger,
        fetch_root_key,
        debug,
    }: HandleRequest,
) -> Result<Response<Body>, Infallible> {
    let request_uri_path = request.uri().path();
    let result = if request_uri_path.starts_with("/api/") {
        slog::debug!(
            logger,
            "URI Request to path '{}' being forwarded to Replica",
            &request.uri().path()
        );
        forward_api(&ip_addr, request, &replica_url).await
    } else if request_uri_path.starts_with("/_/") && !request_uri_path.starts_with("/_/raw") {
        if let Some(proxy_url) = proxy_url {
            slog::debug!(
                logger,
                "URI Request to path '{}' being forwarded to proxy",
                &request.uri().path(),
            );
            forward_api(&ip_addr, request, &proxy_url).await
        } else {
            slog::warn!(
                logger,
                "Unable to proxy {} because no --proxy is configured",
                &request.uri().path()
            );
            not_found()
        }
    } else {
        let transport = ReqwestHttpReplicaV2Transport::create_with_client(replica_url, client)
            .expect("failed to create transport")
            .with_max_response_body_size(RESPONSE_BODY_SIZE_LIMIT);

        let agent = Arc::new(
            ic_agent::Agent::builder()
                .with_transport(transport)
                .build()
                .expect("Could not create agent..."),
        );

        if fetch_root_key && agent.fetch_root_key().await.is_err() {
            unable_to_fetch_root_key()
        } else {
            forward_request(
                request,
                agent,
                resolver.as_ref(),
                validator.as_ref(),
                logger.clone(),
            )
            .await
        }
    };

    match result {
        Err(err) => {
            slog::warn!(logger, "Internal Error during request:\n{:#?}", err);

            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(if debug {
                    format!("Internal Error: {:?}", err).into()
                } else {
                    "Internal Server Error".into()
                })
                .unwrap())
        }
        Ok(x) => Ok::<_, Infallible>(x),
    }
}

fn setup_http_client(
    logger: &slog::Logger,
    danger_accept_invalid_certs: bool,
    root_certificates: &[PathBuf],
    addr_mappings: Vec<OptResolve>,
) -> reqwest::Client {
    let builder = rustls::ClientConfig::builder().with_safe_defaults();
    let mut tls_config = if !danger_accept_invalid_certs {
        use rustls::Certificate;
        use rustls::RootCertStore;

        let mut root_cert_store = RootCertStore::empty();
        for cert_path in root_certificates {
            let mut buf = Vec::new();
            if let Err(e) = File::open(cert_path).and_then(|mut v| v.read_to_end(&mut buf)) {
                slog::warn!(
                    logger,
                    "Could not load cert `{}`: {}",
                    cert_path.display(),
                    e
                );
                continue;
            }
            match cert_path.extension() {
                Some(v) if v == "pem" => {
                    slog::info!(
                        logger,
                        "adding PEM cert `{}` to root certificates",
                        cert_path.display()
                    );
                    let mut pem = Cursor::new(buf);
                    let certs = match rustls_pemfile::certs(&mut pem) {
                        Ok(v) => v,
                        Err(e) => {
                            slog::warn!(
                                logger,
                                "No valid certificate was found `{}`: {}",
                                cert_path.display(),
                                e
                            );
                            continue;
                        }
                    };
                    for c in certs {
                        if let Err(e) = root_cert_store.add(&rustls::Certificate(c)) {
                            slog::warn!(
                                logger,
                                "Could not add part of cert `{}`: {}",
                                cert_path.display(),
                                e
                            );
                        }
                    }
                }
                Some(v) if v == "der" => {
                    slog::info!(
                        logger,
                        "adding DER cert `{}` to root certificates",
                        cert_path.display()
                    );
                    if let Err(e) = root_cert_store.add(&Certificate(buf)) {
                        slog::warn!(
                            logger,
                            "Could not add cert `{}`: {}",
                            cert_path.display(),
                            e
                        );
                    }
                }
                _ => slog::warn!(
                    logger,
                    "Could not load cert `{}`: unknown extension",
                    cert_path.display()
                ),
            }
        }

        use rustls::OwnedTrustAnchor;
        let trust_anchors = webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|trust_anchor| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                trust_anchor.subject,
                trust_anchor.spki,
                trust_anchor.name_constraints,
            )
        });
        root_cert_store.add_server_trust_anchors(trust_anchors);

        builder
            .with_root_certificates(root_cert_store)
            .with_no_client_auth()
    } else {
        use rustls::client::HandshakeSignatureValid;
        use rustls::client::ServerCertVerified;
        use rustls::client::ServerCertVerifier;
        use rustls::client::ServerName;
        use rustls::internal::msgs::handshake::DigitallySignedStruct;

        slog::warn!(logger, "Allowing invalid certs. THIS VERY IS INSECURE.");
        struct NoVerifier;

        impl ServerCertVerifier for NoVerifier {
            fn verify_server_cert(
                &self,
                _end_entity: &rustls::Certificate,
                _intermediates: &[rustls::Certificate],
                _server_name: &ServerName,
                _scts: &mut dyn Iterator<Item = &[u8]>,
                _ocsp_response: &[u8],
                _now: std::time::SystemTime,
            ) -> Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &rustls::Certificate,
                _dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }

            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &rustls::Certificate,
                _dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
        }
        builder
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    };

    // Advertise support for HTTP/2
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let builder = reqwest::Client::builder().use_preconfigured_tls(tls_config);

    // Setup DNS
    let builder = addr_mappings
        .into_iter()
        .fold(builder, |builder, OptResolve { domain, addr }| {
            builder.resolve(&domain, addr)
        });

    builder.build().expect("Could not create HTTP client.")
}

#[derive(Clone)]
struct MetricsHandlerArgs {
    exporter: PrometheusExporter,
}

async fn metrics_handler(
    Extension(MetricsHandlerArgs { exporter }): Extension<MetricsHandlerArgs>,
    _: Request<Body>,
) -> Response<Body> {
    let metric_families = exporter.registry().gather();

    let encoder = TextEncoder::new();

    let mut metrics_text = Vec::new();
    if encoder.encode(&metric_families, &mut metrics_text).is_err() {
        return Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body("Internal Server Error".into())
            .unwrap();
    };

    Response::builder()
        .status(200)
        .body(metrics_text.into())
        .unwrap()
}

fn main() -> Result<(), Box<dyn Error>> {
    let opts: Opts = Opts::parse();

    let logger = logging::setup_logging(&opts);

    let client = setup_http_client(
        &logger,
        opts.danger_accept_invalid_ssl,
        &opts.ssl_root_certificate,
        opts.replica_resolve,
    );

    // Setup metrics
    let exporter = opentelemetry_prometheus::exporter()
        .with_resource(Resource::new(vec![KeyValue::new("service", "prober")]))
        .init();
    let meter = global::meter("icx-proxy");

    let metrics_addr = opts.metrics_addr;
    let create_metrics_server = move || {
        OptionFuture::from(metrics_addr.map(|metrics_addr| {
            let metrics_handler = metrics_handler.layer(Extension(MetricsHandlerArgs { exporter }));
            let metrics_router = Router::new().route("/metrics", get(metrics_handler));

            axum::Server::bind(&metrics_addr).serve(metrics_router.into_make_service())
        }))
    };

    // Prepare a list of agents for each backend replicas.
    let replicas = Mutex::new(opts.replica.clone());

    let dns = DnsCanisterConfig::new(&opts.dns_alias, &opts.dns_suffix)?;
    let resolver = Arc::new(canister_id::DefaultResolver {
        dns,
        check_params: !opts.ignore_url_canister_param,
    });

    let validator = Validator::new();
    let validator = WithMetrics(validator, MetricParams::new(&meter, "validator"));
    let validator = Arc::new(validator);

    let counter = AtomicUsize::new(0);
    let debug = opts.debug;
    let proxy_url = opts.proxy.clone();
    let fetch_root_key = opts.fetch_root_key;

    let service = make_service_fn(|socket: &hyper::server::conn::AddrStream| {
        let ip_addr = socket.remote_addr();
        let ip_addr = ip_addr.ip();
        let resolver = resolver.clone();
        let validator = validator.clone();
        let logger = logger.clone();

        // Select an agent.
        let replica_url_array = replicas.lock().unwrap();
        let count = counter.fetch_add(1, Ordering::SeqCst);
        let replica_url = replica_url_array
            .get(count % replica_url_array.len())
            .unwrap_or_else(|| unreachable!());
        let replica_url = replica_url.clone();
        slog::debug!(logger, "Replica URL: {}", replica_url);

        let proxy_url = proxy_url.clone();
        let client = client.clone();

        async move {
            Ok::<_, Infallible>(service_fn(move |request| {
                handle_request(HandleRequest {
                    ip_addr,
                    request,
                    replica_url: replica_url.clone(),
                    client: client.clone(),
                    proxy_url: proxy_url.clone(),
                    resolver: resolver.clone(),
                    validator: validator.clone(),
                    logger: logger.clone(),
                    fetch_root_key,
                    debug,
                })
            }))
        }
    });

    let address = opts.address;
    slog::info!(logger, "Starting server. Listening on http://{}/", address);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(10)
        .enable_all()
        .build()?;

    rt.block_on(async {
        try_join!(
            create_metrics_server().map(|v| v.transpose()), // metrics
            Server::bind(&address).serve(service),          // icx
        )?;

        Ok(())
    })
}
