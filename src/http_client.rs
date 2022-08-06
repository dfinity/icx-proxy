use std::{
    fs::File,
    io::{Cursor, Read},
    net::SocketAddr,
    path::PathBuf,
    str::FromStr,
    sync::Arc,
};

use anyhow::Context;
use clap::Args;
use tracing::error;

/// Resolve overrides for [`reqwest::ClientBuilder::resolve()`]
/// `ic0.app=[::1]:9090`
struct OptResolve {
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

/// The options for the HTTP client
#[derive(Args)]
pub struct Opts {
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

    /// Override DNS resolution for specific replica domains to particular IP addresses.
    /// Examples: ic0.app=[::1]:9090
    #[clap(long, value_name("DOMAIN=IP_PORT"))]
    replica_resolve: Vec<OptResolve>,
}

pub fn setup(opts: Opts) -> Result<reqwest::Client, anyhow::Error> {
    let Opts {
        danger_accept_invalid_ssl,
        ssl_root_certificate,
        replica_resolve,
    } = opts;
    let builder = rustls::ClientConfig::builder().with_safe_defaults();
    let mut tls_config = if !danger_accept_invalid_ssl {
        use rustls::{Certificate, RootCertStore};

        let mut root_cert_store = RootCertStore::empty();
        for cert_path in ssl_root_certificate {
            let mut buf = Vec::new();
            if let Err(e) = File::open(&cert_path).and_then(|mut v| v.read_to_end(&mut buf)) {
                tracing::warn!("Could not load cert `{}`: {}", cert_path.display(), e);
                continue;
            }
            match cert_path.extension() {
                Some(v) if v == "pem" => {
                    tracing::info!(
                        "adding PEM cert `{}` to root certificates",
                        cert_path.display()
                    );
                    let mut pem = Cursor::new(buf);
                    let certs = match rustls_pemfile::certs(&mut pem) {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!(
                                "No valid certificate was found `{}`: {}",
                                cert_path.display(),
                                e
                            );
                            continue;
                        }
                    };
                    for c in certs {
                        if let Err(e) = root_cert_store.add(&rustls::Certificate(c)) {
                            tracing::warn!(
                                "Could not add part of cert `{}`: {}",
                                cert_path.display(),
                                e
                            );
                        }
                    }
                }
                Some(v) if v == "der" => {
                    tracing::info!(
                        "adding DER cert `{}` to root certificates",
                        cert_path.display()
                    );
                    if let Err(e) = root_cert_store.add(&Certificate(buf)) {
                        tracing::warn!("Could not add cert `{}`: {}", cert_path.display(), e);
                    }
                }
                _ => tracing::warn!(
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
        use rustls::{
            client::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier, ServerName},
            internal::msgs::handshake::DigitallySignedStruct,
        };

        tracing::warn!("Allowing invalid certs. THIS VERY IS INSECURE.");
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
    let builder = replica_resolve
        .into_iter()
        .fold(builder, |builder, OptResolve { domain, addr }| {
            builder.resolve(&domain, addr)
        });

    let v = builder.build().context("Could not create HTTP client.");
    if let Err(e) = v.as_ref() {
        error!("{}", e)
    }
    v
}
