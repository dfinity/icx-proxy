use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use axum::{extract::ConnectInfo, Extension};
use hyper::{client::HttpConnector, http::uri::Parts, Body, Client, Request, Response, Uri};
use hyper_tls::HttpsConnector;
use tracing::{info, instrument};

use crate::proxy::handle_error;

pub struct Args {
    pub debug: bool,
    pub proxy_url: Uri,
    pub client: Client<HttpsConnector<HttpConnector>>,
}

#[instrument(level = "info", skip_all, fields(addr = display(addr)))]
pub async fn handler(
    Extension(args): Extension<Arc<Args>>,
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
