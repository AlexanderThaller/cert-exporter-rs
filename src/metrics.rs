use std::collections::HashSet;

use prometheus_exporter::prometheus::{
    register_int_gauge_vec,
    IntGaugeVec,
};
use thiserror::Error;

use crate::certificate::Certificate;

#[derive(Debug, Error)]
pub enum Error {}

#[derive(Debug)]
pub struct Metrics {
    not_before: IntGaugeVec,
    not_after: IntGaugeVec,
}

pub fn new() -> Metrics {
    const NAMESPACE: &str = "cert_exporter_rs";

    let not_before = register_int_gauge_vec!(
        format!("{}_not_before_timestamp", NAMESPACE),
        "unix time before which the certificate is invalid",
        &["common_name"]
    )
    .unwrap();

    let not_after = register_int_gauge_vec!(
        format!("{}_not_after_timestamp", NAMESPACE),
        "unix time after which the certificate is invalid",
        &["common_name"]
    )
    .unwrap();

    Metrics {
        not_before,
        not_after,
    }
}

impl Metrics {
    pub fn update(&mut self, certificates: HashSet<Certificate>) -> Result<(), Error> {
        self.not_before.reset();
        self.not_after.reset();

        certificates.into_iter().for_each(|cert| {
            cert.common_names.iter().for_each(|common_name| {
                self.not_before
                    .with_label_values(&[common_name])
                    .set(cert.not_before.timestamp());

                self.not_after
                    .with_label_values(&[common_name])
                    .set(cert.not_after.timestamp())
            })
        });

        Ok(())
    }
}
