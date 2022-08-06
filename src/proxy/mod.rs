use std::{
    future::Future,
    net::SocketAddr,
    sync::{atomic::AtomicUsize, Arc},
};

use anyhow::{bail, Context};
use axum::{handler::Handler, routing::any, Extension, Router};
use clap::Args;
use hyper::{Body, Client, Response, StatusCode, Uri};
use ic_agent::{
    agent::http_transport::{reqwest, ReqwestHttpReplicaV2Transport},
    Agent,
};
use tracing::{error, info};

use crate::{
    canister_id::Resolver as CanisterIdResolver, logging::add_trace_layer, validate::Validate,
};

const KB: usize = 1024;
const MB: usize = 1024 * KB;

const REQUEST_BODY_SIZE_LIMIT: usize = 10 * MB;
const RESPONSE_BODY_SIZE_LIMIT: usize = 10 * MB;

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

mod agent;

use agent::{handler as agent_handler, Args as AgentArgs, ArgsInner as AgentArgsInner};

mod forward;

use forward::{handler as forward_handler, Args as ForwardArgs};

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
    let agent_args = Extension(AgentArgs::from(AgentArgsInner {
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
    let agent_handler = agent_handler.layer(agent_args).into_service();

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
        let forward_handler = any(forward_handler.layer(forward_args));
        router
            // Exclude `/_/raw` from the proxy
            .route("/_/raw", agent_handler.clone())
            .route("/_/raw/*path", agent_handler.clone())
            // Include everything else
            .route("/_", forward_handler.clone())
            .route("/_/", forward_handler.clone())
            .route("/_/:not_raw", forward_handler.clone())
            .route("/_/:not_raw/*path", forward_handler)
    } else {
        router
    };

    Ok(Runner {
        router: add_trace_layer(router.fallback(agent_handler)),
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
