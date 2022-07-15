use opentelemetry::{
    metrics::{Counter, Meter},
    KeyValue,
};

use crate::validate::Validate;

pub struct WithMetrics<T>(pub T, pub MetricParams);

pub struct MetricParams {
    pub counter: Counter<u64>,
}

impl MetricParams {
    pub fn new(meter: &Meter, name: &str) -> Self {
        Self {
            counter: meter
                .u64_counter(format!("{name}.total"))
                .with_description(format!("Counts occurences of {name} calls"))
                .init(),
        }
    }
}

impl<T: Validate> Validate for WithMetrics<T> {
    fn validate(
        &self,
        headers_data: &crate::headers::HeadersData,
        canister_id: &candid::Principal,
        agent: &ic_agent::Agent,
        uri: &hyper::Uri,
        response_body: &[u8],
        logger: slog::Logger,
    ) -> Result<(), String> {
        let out = self
            .0
            .validate(headers_data, canister_id, agent, uri, response_body, logger);

        let status = if out.is_ok() { "ok" } else { "fail" };

        let labels = &[KeyValue::new("status", status)];

        let MetricParams { counter } = &self.1;
        counter.add(1, labels);

        out
    }
}
