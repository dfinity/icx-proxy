use std::io::Read;

use candid::Principal;
use flate2::read::{DeflateDecoder, GzDecoder};
use hyper::Uri;
use ic_agent::{
    hash_tree::LookupResult, ic_types::HashTree, lookup_value, Agent, AgentError, Certificate,
};
use sha2::{Digest, Sha256};

use crate::HeadersData;

// The limit of a buffer we should decompress ~10mb.
const MAX_CHUNK_SIZE_TO_DECOMPRESS: usize = 1024;
const MAX_CHUNKS_TO_DECOMPRESS: u64 = 10_240;

pub trait Validate: Sync + Send {
    fn validate(
        &self,
        headers_data: &HeadersData,
        canister_id: &Principal,
        agent: &Agent,
        uri: &Uri,
        response_body: &[u8],
        logger: slog::Logger,
    ) -> Result<(), String>;
}

pub struct Validator {}

impl Validator {
    pub fn new() -> Self {
        Self {}
    }
}

impl Validate for Validator {
    fn validate(
        &self,
        headers_data: &HeadersData,
        canister_id: &Principal,
        agent: &Agent,
        uri: &Uri,
        response_body: &[u8],
        logger: slog::Logger,
    ) -> Result<(), String> {
        let body_sha = if let Some(body_sha) =
            decode_body_to_sha256(response_body, headers_data.encoding.clone())
        {
            body_sha
        } else {
            return Err("Body could not be decoded".into());
        };

        let body_valid = match (
            headers_data.certificate.as_ref(),
            headers_data.tree.as_ref(),
        ) {
            (Some(Ok(certificate)), Some(Ok(tree))) => match validate_body(
                Certificates { certificate, tree },
                canister_id,
                agent,
                uri,
                &body_sha,
                logger.clone(),
            ) {
                Ok(true) => Ok(()),
                Ok(false) => Err("Body does not pass verification".to_string()),
                Err(e) => Err(format!("Certificate validation failed: {}", e)),
            },
            (Some(_), _) | (_, Some(_)) => Err("Body does not pass verification".to_string()),

            // TODO: Remove this (FOLLOW-483)
            // Canisters don't have to provide certified variables
            // This should change in the future, grandfathering in current implementations
            (None, None) => Ok(()),
        };

        if cfg!(feature = "skip_body_verification") {
            return Ok(());
        }

        body_valid
    }
}

struct Certificates<'a> {
    certificate: &'a Vec<u8>,
    tree: &'a Vec<u8>,
}

fn decode_body_to_sha256(body: &[u8], encoding: Option<String>) -> Option<[u8; 32]> {
    let mut sha256 = Sha256::new();
    let mut decoded = [0u8; MAX_CHUNK_SIZE_TO_DECOMPRESS];
    match encoding.as_deref() {
        Some("gzip") => {
            let mut decoder = GzDecoder::new(body);
            for _ in 0..MAX_CHUNKS_TO_DECOMPRESS {
                let bytes = decoder.read(&mut decoded).ok()?;
                if bytes == 0 {
                    return Some(sha256.finalize().into());
                }
                sha256.update(&decoded[0..bytes]);
            }
            if decoder.bytes().next().is_some() {
                return None;
            }
        }
        Some("deflate") => {
            let mut decoder = DeflateDecoder::new(body);
            for _ in 0..MAX_CHUNKS_TO_DECOMPRESS {
                let bytes = decoder.read(&mut decoded).ok()?;
                if bytes == 0 {
                    return Some(sha256.finalize().into());
                }
                sha256.update(&decoded[0..bytes]);
            }
            if decoder.bytes().next().is_some() {
                return None;
            }
        }
        _ => sha256.update(body),
    };
    Some(sha256.finalize().into())
}

fn validate_body(
    certificates: Certificates,
    canister_id: &Principal,
    agent: &Agent,
    uri: &Uri,
    body_sha: &[u8; 32],
    logger: slog::Logger,
) -> anyhow::Result<bool> {
    let cert: Certificate =
        serde_cbor::from_slice(certificates.certificate).map_err(AgentError::InvalidCborData)?;
    let tree: HashTree =
        serde_cbor::from_slice(certificates.tree).map_err(AgentError::InvalidCborData)?;

    if let Err(e) = agent.verify(&cert, *canister_id, false) {
        slog::trace!(logger, ">> certificate failed verification: {}", e);
        return Ok(false);
    }

    let certified_data_path = vec![
        "canister".into(),
        canister_id.into(),
        "certified_data".into(),
    ];
    let witness = match lookup_value(&cert, certified_data_path) {
        Ok(witness) => witness,
        Err(e) => {
            slog::trace!(
                logger,
                ">> Could not find certified data for this canister in the certificate: {}",
                e
            );
            return Ok(false);
        }
    };
    let digest = tree.digest();

    if witness != digest {
        slog::trace!(
            logger,
            ">> witness ({}) did not match digest ({})",
            hex::encode(witness),
            hex::encode(digest)
        );

        return Ok(false);
    }

    let path = ["http_assets".into(), uri.path().into()];
    let tree_sha = match tree.lookup_path(&path) {
        LookupResult::Found(v) => v,
        _ => match tree.lookup_path(&["http_assets".into(), "/index.html".into()]) {
            LookupResult::Found(v) => v,
            _ => {
                slog::trace!(
                    logger,
                    ">> Invalid Tree in the header. Does not contain path {:?}",
                    path
                );
                return Ok(false);
            }
        },
    };

    Ok(body_sha == tree_sha)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use candid::Principal;
    use hyper::Uri;
    use ic_agent::{agent::http_transport::ReqwestHttpReplicaV2Transport, Agent};
    use slog::o;

    use crate::{
        headers::HeadersData,
        validate::{Validate, Validator},
    };

    #[test]
    fn validate_nop() {
        let headers = HeadersData {
            certificate: None,
            encoding: None,
            tree: None,
        };

        let canister_id = Principal::from_text("wwc2m-2qaaa-aaaac-qaaaa-cai").unwrap();
        let transport = ReqwestHttpReplicaV2Transport::create("http://www.example.com").unwrap();
        let agent = Agent::builder().with_transport(transport).build().unwrap();
        let uri = Uri::from_str("http://www.example.com").unwrap();
        let body = vec![];
        let logger = slog::Logger::root(slog::Discard, o!());

        let validator = Validator::new();

        let out = validator.validate(&headers, &canister_id, &agent, &uri, &body, logger);

        assert_eq!(out, Ok(()));
    }
}
