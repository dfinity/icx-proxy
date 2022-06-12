use hyper::{header::HOST, Request, Uri};
use ic_agent::export::Principal;

use crate::config::dns_canister_config::DnsCanisterConfig;

/// A resolver for `Principal`s from a `Uri`.
trait UriCanisterIdResolver: Sync + Send {
    fn resolve(&self, uri: &Uri) -> Option<Principal>;
}

impl<T: UriCanisterIdResolver> UriCanisterIdResolver for &T {
    fn resolve(&self, uri: &Uri) -> Option<Principal> {
        T::resolve(self, uri)
    }
}

struct UriParameterResolver;

impl UriCanisterIdResolver for UriParameterResolver {
    fn resolve(&self, uri: &Uri) -> Option<Principal> {
        url::form_urlencoded::parse(uri.query()?.as_bytes())
            .find(|(name, _)| name == "canisterId")
            .and_then(|(_, canister_id)| Principal::from_text(canister_id.as_ref()).ok())
    }
}

impl UriCanisterIdResolver for DnsCanisterConfig {
    fn resolve(&self, uri: &Uri) -> Option<Principal> {
        self.resolve_canister_id(uri.host()?)
    }
}

/// A resolver for `Principal`s from a `Request`.
pub trait CanisterIdResolver<B>: Sync + Send {
    fn resolve(&self, request: &Request<B>) -> Option<Principal>;
}

impl<B, T: CanisterIdResolver<B>> CanisterIdResolver<B> for &T {
    fn resolve(&self, request: &Request<B>) -> Option<Principal> {
        T::resolve(self, request)
    }
}

struct RequestUriResolver<T>(pub T);

impl<B, T: UriCanisterIdResolver> CanisterIdResolver<B> for RequestUriResolver<T> {
    fn resolve(&self, request: &Request<B>) -> Option<Principal> {
        self.0.resolve(request.uri())
    }
}

struct RequestHostResolver<T>(pub T);

impl<B, T: UriCanisterIdResolver> CanisterIdResolver<B> for RequestHostResolver<T> {
    fn resolve(&self, request: &Request<B>) -> Option<Principal> {
        self.0.resolve(
            &Uri::builder()
                .authority(request.headers().get(HOST)?.as_bytes())
                .build()
                .ok()?,
        )
    }
}

/// The default canister id resolver
pub struct DefaultCanisterIdResolver {
    pub dns: DnsCanisterConfig,
    pub check_params: bool,
}

impl<B> CanisterIdResolver<B> for DefaultCanisterIdResolver {
    fn resolve(&self, request: &Request<B>) -> Option<Principal> {
        if let Some(v) = RequestHostResolver(&self.dns).resolve(request) {
            return Some(v);
        }
        if let Some(v) = RequestUriResolver(&self.dns).resolve(request) {
            return Some(v);
        }
        if self.check_params {
            if let Some(v) = RequestUriResolver(UriParameterResolver).resolve(request) {
                return Some(v);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use hyper::{header::HOST, Request};
    use ic_agent::export::Principal;

    use super::{CanisterIdResolver, DefaultCanisterIdResolver};
    use crate::config::dns_canister_config::DnsCanisterConfig;

    #[test]
    fn simple_resolve() {
        let dns = parse_config(
            vec!["happy.little.domain.name:r7inp-6aaaa-aaaaa-aaabq-cai"],
            vec!["little.domain.name"],
        );

        let resolver = DefaultCanisterIdResolver {
            dns,
            check_params: false,
        };

        let req = build_req(
            Some("happy.little.domain.name"),
            "https://happy.little.domain.name/rrkah-fqaaa-aaaaa-aaaaq-cai",
        );

        assert_eq!(
            resolver.resolve(&req),
            Some(principal("r7inp-6aaaa-aaaaa-aaabq-cai"))
        );

        let req = build_req(
            Some("rrkah-fqaaa-aaaaa-aaaaq-cai.little.domain.name"),
            "/r7inp-6aaaa-aaaaa-aaabq-cai",
        );

        assert_eq!(
            resolver.resolve(&req),
            Some(principal("rrkah-fqaaa-aaaaa-aaaaq-cai"))
        );
    }

    #[test]
    fn prod() {
        let dns = parse_config(
            vec![
                "personhood.ic0.app:g3wsl-eqaaa-aaaan-aaaaa-cai",
                "personhood.raw.ic0.app:g3wsl-eqaaa-aaaan-aaaaa-cai",
                "identity.ic0.app:rdmx6-jaaaa-aaaaa-aaadq-cai",
                "identity.raw.ic0.app:rdmx6-jaaaa-aaaaa-aaadq-cai",
                "nns.ic0.app:qoctq-giaaa-aaaaa-aaaea-cai",
                "nns.raw.ic0.app:qoctq-giaaa-aaaaa-aaaea-cai",
                "dscvr.ic0.app:h5aet-waaaa-aaaab-qaamq-cai",
                "dscvr.raw.ic0.app:h5aet-waaaa-aaaab-qaamq-cai",
            ],
            vec!["raw.ic0.app", "ic0.app"],
        );

        let resolver = DefaultCanisterIdResolver {
            dns,
            check_params: false,
        };

        let req = build_req(Some("nns.ic0.app"), "/about");
        assert_eq!(
            resolver.resolve(&req),
            Some(principal("qoctq-giaaa-aaaaa-aaaea-cai"))
        );

        let req = build_req(Some("nns.ic0.app"), "https://nns.ic0.app/about");
        assert_eq!(
            resolver.resolve(&req),
            Some(principal("qoctq-giaaa-aaaaa-aaaea-cai"))
        );

        let req = build_req(None, "https://nns.ic0.app/about");
        assert_eq!(
            resolver.resolve(&req),
            Some(principal("qoctq-giaaa-aaaaa-aaaea-cai"))
        );

        let req = build_req(None, "https://rrkah-fqaaa-aaaaa-aaaaq-cai.ic0.app/about");
        assert_eq!(
            resolver.resolve(&req),
            Some(principal("rrkah-fqaaa-aaaaa-aaaaq-cai"))
        );

        let req = build_req(
            Some("rrkah-fqaaa-aaaaa-aaaaq-cai.ic0.app"),
            "https://rrkah-fqaaa-aaaaa-aaaaq-cai.ic0.app/about",
        );
        assert_eq!(
            resolver.resolve(&req),
            Some(principal("rrkah-fqaaa-aaaaa-aaaaq-cai"))
        );

        let req = build_req(Some("rrkah-fqaaa-aaaaa-aaaaq-cai.ic0.app"), "/about");
        assert_eq!(
            resolver.resolve(&req),
            Some(principal("rrkah-fqaaa-aaaaa-aaaaq-cai"))
        );

        let req = build_req(Some("rrkah-fqaaa-aaaaa-aaaaq-cai.raw.ic0.app"), "/about");
        assert_eq!(
            resolver.resolve(&req),
            Some(principal("rrkah-fqaaa-aaaaa-aaaaq-cai"))
        );

        let req = build_req(
            Some("rrkah-fqaaa-aaaaa-aaaaq-cai.foo.raw.ic0.app"),
            "/about",
        );
        assert_eq!(resolver.resolve(&req), None);
    }

    #[test]
    fn dfx() {
        let dns = parse_config(vec![], vec!["localhost"]);

        let resolver = DefaultCanisterIdResolver {
            dns,
            check_params: true,
        };

        let req = build_req(Some("rrkah-fqaaa-aaaaa-aaaaq-cai.localhost"), "/about");
        assert_eq!(
            resolver.resolve(&req),
            Some(principal("rrkah-fqaaa-aaaaa-aaaaq-cai"))
        );
        let req = build_req(
            Some("localhost"),
            "/about?canisterId=rrkah-fqaaa-aaaaa-aaaaq-cai",
        );
        assert_eq!(
            resolver.resolve(&req),
            Some(principal("rrkah-fqaaa-aaaaa-aaaaq-cai"))
        );
    }

    fn parse_config(aliases: Vec<&str>, suffixes: Vec<&str>) -> DnsCanisterConfig {
        let aliases: Vec<String> = aliases.iter().map(|&s| String::from(s)).collect();
        let suffixes: Vec<String> = suffixes.iter().map(|&s| String::from(s)).collect();
        DnsCanisterConfig::new(&aliases, &suffixes).unwrap()
    }

    fn build_req(host: Option<&str>, uri: &str) -> Request<()> {
        let req = Request::builder().uri(uri);
        if let Some(host) = host {
            req.header(HOST, host)
        } else {
            req
        }
        .body(())
        .unwrap()
    }

    fn principal(v: &str) -> Principal {
        Principal::from_text(v).unwrap()
    }
}
