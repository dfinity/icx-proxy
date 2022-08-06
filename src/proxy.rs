use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use anyhow::{bail, Context};
use axum::{extract::ConnectInfo, handler::Handler, routing::any, Extension, Router};
use clap::Args;
use futures::StreamExt;
use http_body::{LengthLimitError, Limited};
use hyper::{
    body,
    client::HttpConnector,
    http::{header::CONTENT_TYPE, uri::Parts},
    Body, Client, Request, Response, StatusCode, Uri,
};
use hyper_tls::HttpsConnector;
use ic_agent::{
    agent::http_transport::{reqwest, ReqwestHttpReplicaV2Transport},
    agent_error::HttpErrorPayload,
    Agent, AgentError,
};
use ic_utils::{
    call::{AsyncCall, SyncCall},
    interfaces::http_request::{
        HeaderField, HttpRequestCanister, HttpRequestStreamingCallbackAny, HttpResponse,
        StreamingCallbackHttpResponse, StreamingStrategy, Token,
    },
};
use tracing::{enabled, error, info, instrument, trace, warn, Level};

use crate::{
    canister_id::Resolver as CanisterIdResolver, headers::extract_headers_data,
    logging::add_trace_layer, validate::Validate,
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

/// https://internetcomputer.org/docs/current/references/ic-interface-spec#reject-codes
struct ReplicaErrorCodes;
impl ReplicaErrorCodes {
    const DESTINATION_INVALID: u64 = 3;
}

/// The options for the proxy server
#[derive(Args)]
pub struct Opts {
    /// The address to bind to.
    #[clap(long, default_value = "127.0.0.1:3000")]
    address: SocketAddr,

    /// A replica to use as backend. Locally, this should be a local instance or the
    /// boundary node. Multiple replicas can be passed and they'll be used round-robin.
    #[clap(long, default_value = "http://localhost:8000/")]
    replica: Vec<String>,

    /// An address to forward any requests from /_/
    #[clap(long)]
    proxy: Option<Uri>,

    /// Whether or not this is run in a debug context (e.g. errors returned in responses
    /// should show full stack and error details).
    #[clap(long)]
    debug: bool,

    /// Whether or not to fetch the root key from the replica back end. Do not use this when
    /// talking to the Internet Computer blockchain mainnet as it is unsecure.
    #[clap(long)]
    fetch_root_key: bool,
}

struct ProcessArgsInner {
    validator: Box<dyn Validate>,
    resolver: Box<dyn CanisterIdResolver<Body>>,
    counter: AtomicUsize,
    replicas: Vec<(Agent, String)>,
    debug: bool,
    fetch_root_key: bool,
}

struct ProcessArgs {
    args: Arc<ProcessArgsInner>,
    current: usize,
}

impl Clone for ProcessArgs {
    fn clone(&self) -> Self {
        let args = self.args.clone();
        ProcessArgs {
            current: args.counter.fetch_add(1, Ordering::Relaxed) % args.replicas.len(),
            args,
        }
    }
}

impl From<ProcessArgsInner> for ProcessArgs {
    fn from(args: ProcessArgsInner) -> Self {
        ProcessArgs {
            args: Arc::new(args),
            current: 0,
        }
    }
}
impl ProcessArgs {
    fn replica(&self) -> (&Agent, &str) {
        let v = &self.args.replicas[self.current];
        (&v.0, &v.1)
    }
}

#[instrument(level = "info", skip_all, fields(addr = display(addr), replica = args.replica().1))]
async fn process_request(
    Extension(args): Extension<ProcessArgs>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    let agent = args.replica().0;
    let args = &args.args;
    handle_error(
        args.debug,
        async {
            if args.fetch_root_key && agent.fetch_root_key().await.is_err() {
                unable_to_fetch_root_key()
            } else {
                process_request_inner(
                    request,
                    agent,
                    args.resolver.as_ref(),
                    args.validator.as_ref(),
                )
                .await
            }
        }
        .await,
    )
}

fn unable_to_fetch_root_key() -> Result<Response<Body>, anyhow::Error> {
    Ok(Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body("Unable to fetch root key".into())?)
}

async fn process_request_inner(
    request: Request<Body>,
    agent: &Agent,
    resolver: &dyn CanisterIdResolver<Body>,
    validator: &dyn Validate,
) -> Result<Response<Body>, anyhow::Error> {
    let canister_id = match resolver.resolve(&request) {
        None => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("Could not find a canister id to forward to.".into())
                .unwrap())
        }
        Some(x) => x,
    };

    trace!(
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
            trace!("<< {}: {}", name, value);
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
            bail!("Failed to read body: {err}");
        }
    }
    .to_vec();

    trace!("<<");
    if enabled!(Level::TRACE) {
        let body = String::from_utf8_lossy(
            &entire_body[0..usize::min(entire_body.len(), MAX_LOG_BODY_SIZE)],
        );
        trace!(
            "<< \"{}\"{}",
            &body.escape_default(),
            if body.len() > MAX_LOG_BODY_SIZE {
                format!("... {} bytes total", body.len())
            } else {
                String::new()
            }
        );
    }

    let canister = HttpRequestCanister::create(agent, canister_id);
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
    ) -> Result<HttpResponseAny, Result<Response<Body>, anyhow::Error>> {
        // If the result is a Replica error, returns the 500 code and message. There is no information
        // leak here because a user could use `dfx` to get the same reply.
        match result {
            Ok((http_response,)) => Ok(http_response),

            Err(AgentError::ReplicaError {
                reject_code: ReplicaErrorCodes::DESTINATION_INVALID,
                reject_message,
            }) => Err(Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(reject_message.into())
                .unwrap())),

            Err(AgentError::ReplicaError {
                reject_code,
                reject_message,
            }) => Err(Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
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

    let headers_data = extract_headers_data(&http_response.headers);
    let body = if enabled!(Level::TRACE) {
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
                    (agent.clone(), callback.callback.0, Some(callback.token)),
                    move |(agent, callback, callback_token)| async move {
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
                                Ok(Some((body, (agent, callback, token))))
                            }
                            Err(e) => {
                                warn!("Error happened during streaming: {}", e);
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
        );
        if body_valid.is_err() {
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(body_valid.unwrap_err().into())
                .unwrap());
        }
        builder.body(http_response.body.into())?
    };

    if enabled!(Level::TRACE) {
        trace!(
            ">> {:?} {} {}",
            &response.version(),
            response.status().as_u16(),
            response.status().to_string()
        );

        for (name, value) in response.headers() {
            let value = String::from_utf8_lossy(value.as_bytes());
            trace!(">> {}: {}", name, value);
        }

        let body = body.unwrap_or_else(|| b"... streaming ...".to_vec());

        trace!(">>");
        trace!(
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

struct ForwardArgs {
    debug: bool,
    proxy_url: Uri,
    client: Client<HttpsConnector<HttpConnector>>,
}

#[instrument(level = "info", skip_all, fields(addr = display(addr)))]
async fn forward_request(
    Extension(args): Extension<Arc<ForwardArgs>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    handle_error(
        args.debug,
        async {
            info!("forwarding");
            let proxied_request =
                create_proxied_request(&addr.ip(), args.proxy_url.clone(), request)?;
            let response = args.client.request(proxied_request).await?;
            Ok(response)
        }
        .await,
    )
}

fn create_proxied_request<B>(
    client_ip: &IpAddr,
    proxy_url: Uri,
    mut request: Request<B>,
) -> Result<Request<B>, anyhow::Error> {
    *request.headers_mut() = remove_hop_headers(request.headers());
    *request.uri_mut() = forward_uri(proxy_url, &request)?;

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

fn is_hop_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("proxy-authenticate")
        || name.eq_ignore_ascii_case("proxy-authorization")
        || name.eq_ignore_ascii_case("te")
        || name.eq_ignore_ascii_case("trailers")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("upgrade")
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

fn forward_uri<B>(proxy_url: Uri, req: &Request<B>) -> Result<Uri, anyhow::Error> {
    let mut parts = Parts::from(proxy_url);
    parts.path_and_query = req.uri().path_and_query().cloned();
    Ok(Uri::from_parts(parts)?)
}

fn handle_error(debug: bool, v: Result<Response<Body>, anyhow::Error>) -> Response<Body> {
    match v {
        Err(err) => {
            error!("Internal Error during request:\n{}", err);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(if debug {
                    format!("Internal Error: {:?}", err).into()
                } else {
                    "Internal Server Error".into()
                })
                .unwrap()
        }
        Ok(v) => v,
    }
}

pub struct SetupArgs<V, R> {
    pub validator: V,
    pub resolver: R,
    pub client: reqwest::Client,
}

pub fn setup(
    args: SetupArgs<impl Validate + 'static, impl CanisterIdResolver<Body> + 'static>,
    opts: Opts,
) -> Result<Runner, anyhow::Error> {
    let client = args.client;
    let process_args = Extension(ProcessArgs::from(ProcessArgsInner {
        validator: Box::new(args.validator),
        resolver: Box::new(args.resolver),
        counter: AtomicUsize::new(0),
        replicas: opts
            .replica
            .into_iter()
            .map(|replica_url| {
                let transport = ReqwestHttpReplicaV2Transport::create_with_client(
                    replica_url.clone(),
                    client.clone(),
                )
                .context("failed to create transport")?
                .with_max_response_body_size(RESPONSE_BODY_SIZE_LIMIT);

                let agent = Agent::builder()
                    .with_transport(transport)
                    .build()
                    .context("Could not create agent...")?;
                Ok((agent, replica_url))
            })
            .collect::<Result<_, anyhow::Error>>()?,
        debug: opts.debug,
        fetch_root_key: opts.fetch_root_key,
    }));

    let router = Router::new();
    let process_request = process_request.layer(process_args).into_service();

    // Setup `/_/` proxy for dfx if requested
    let router = if let Some(proxy_url) = opts.proxy {
        info!("Setting up `/_/` proxy to `{proxy_url}`");
        if proxy_url.scheme().is_none() {
            bail!("No schema found on `proxy_url`");
        }
        let forward_args = Extension(Arc::new(ForwardArgs {
            client: Client::builder().build(hyper_tls::HttpsConnector::new()),
            proxy_url,
            debug: opts.debug,
        }));
        let forward_request = any(forward_request.layer(forward_args.clone()));
        router
            // Exclude `/_/raw` from the proxy
            .route("/_/raw", process_request.clone())
            .route("/_/raw/*path", process_request.clone())
            // Include everything else
            .route("/_", forward_request.clone())
            .route("/_/", forward_request.clone())
            .route("/_/:not_raw", forward_request.clone())
            .route("/_/:not_raw/*path", forward_request)
    } else {
        router
    };

    Ok(Runner {
        router: add_trace_layer(router.fallback(process_request)),
        address: opts.address,
    })
}

pub struct Runner {
    router: Router,
    address: SocketAddr,
}
impl Runner {
    pub fn run(self) -> impl Future<Output = Result<(), hyper::Error>> {
        info!("Starting server. Listening on http://{}/", self.address);
        axum::Server::bind(&self.address).serve(
            self.router
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
    }
}
