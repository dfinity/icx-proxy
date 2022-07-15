use ic_utils::interfaces::http_request::HeaderField;
use lazy_regex::regex_captures;

const MAX_LOG_CERT_NAME_SIZE: usize = 100;
const MAX_LOG_CERT_B64_SIZE: usize = 2000;

pub struct HeadersData {
    pub certificate: Option<Result<Vec<u8>, ()>>,
    pub tree: Option<Result<Vec<u8>, ()>>,
    pub encoding: Option<String>,
}

pub fn extract_headers_data(headers: &[HeaderField], logger: &slog::Logger) -> HeadersData {
    let mut headers_data = HeadersData {
        certificate: None,
        tree: None,
        encoding: None,
    };

    for HeaderField(name, value) in headers {
        if name.eq_ignore_ascii_case("IC-CERTIFICATE") {
            for field in value.split(',') {
                if let Some((_, name, b64_value)) = regex_captures!("^(.*)=:(.*):$", field.trim()) {
                    slog::trace!(
                        logger,
                        ">> certificate {:.l1$}: {:.l2$}",
                        name,
                        b64_value,
                        l1 = MAX_LOG_CERT_NAME_SIZE,
                        l2 = MAX_LOG_CERT_B64_SIZE
                    );
                    let bytes = decode_hash_tree(name, Some(b64_value.to_string()), logger);
                    if name == "certificate" {
                        headers_data.certificate = Some(match (headers_data.certificate, bytes) {
                            (None, bytes) => bytes,
                            (Some(Ok(certificate)), Ok(bytes)) => {
                                slog::warn!(logger, "duplicate certificate field: {:?}", bytes);
                                Ok(certificate)
                            }
                            (Some(Ok(certificate)), Err(_)) => {
                                slog::warn!(
                                    logger,
                                    "duplicate certificate field (failed to decode)"
                                );
                                Ok(certificate)
                            }
                            (Some(Err(_)), bytes) => {
                                slog::warn!(
                                    logger,
                                    "duplicate certificate field (failed to decode)"
                                );
                                bytes
                            }
                        });
                    } else if name == "tree" {
                        headers_data.tree = Some(match (headers_data.tree, bytes) {
                            (None, bytes) => bytes,
                            (Some(Ok(tree)), Ok(bytes)) => {
                                slog::warn!(logger, "duplicate tree field: {:?}", bytes);
                                Ok(tree)
                            }
                            (Some(Ok(tree)), Err(_)) => {
                                slog::warn!(logger, "duplicate tree field (failed to decode)");
                                Ok(tree)
                            }
                            (Some(Err(_)), bytes) => {
                                slog::warn!(logger, "duplicate tree field (failed to decode)");
                                bytes
                            }
                        });
                    }
                }
            }
        } else if name.eq_ignore_ascii_case("CONTENT-ENCODING") {
            let enc = value.trim().to_string();
            headers_data.encoding = Some(enc);
        }
    }

    headers_data
}

fn decode_hash_tree(
    name: &str,
    value: Option<String>,
    logger: &slog::Logger,
) -> Result<Vec<u8>, ()> {
    match value {
        Some(tree) => base64::decode(tree).map_err(|e| {
            slog::warn!(logger, "Unable to decode {} from base64: {}", name, e);
        }),
        _ => Err(()),
    }
}
