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
    not_after: IntGaugeVec,
    not_before: IntGaugeVec,
    time_to_expiration: IntGaugeVec,
}

pub fn new() -> Metrics {
    const NAMESPACE: &str = "cert_exporter_rs";

    let not_after = register_int_gauge_vec!(
        format!("{}_not_after_timestamp", NAMESPACE),
        "unix time after which the certificate is invalid",
        &["common_name"]
    )
    .unwrap();

    let not_before = register_int_gauge_vec!(
        format!("{}_not_before_timestamp", NAMESPACE),
        "unix time before which the certificate is invalid",
        &["common_name"]
    )
    .unwrap();

    let time_to_expiration = register_int_gauge_vec!(
        format!("{}_time_to_expiration_seconds", NAMESPACE),
        "time in seconds until when the certificate expires",
        &["common_name"]
    )
    .unwrap();

    let version = register_int_gauge_vec!(
        format!("{}_version", NAMESPACE),
        "version of running instance of cert-exporter-rs",
        &["version"]
    )
    .unwrap();

    version
        .with_label_values(&[structopt::clap::crate_version!()])
        .set(1);

    Metrics {
        not_after,
        not_before,
        time_to_expiration,
    }
}

impl Metrics {
    pub fn update(&mut self, certificates: HashSet<Certificate>) {
        self.time_to_expiration.reset();
        self.not_before.reset();
        self.not_after.reset();

        for cert in certificates {
            cert.common_names.iter().for_each(|common_name| {
                self.time_to_expiration
                    .with_label_values(&[common_name])
                    .set(cert.time_to_expiration.whole_seconds());

                self.not_before
                    .with_label_values(&[common_name])
                    .set(cert.not_before.timestamp());

                self.not_after
                    .with_label_values(&[common_name])
                    .set(cert.not_after.timestamp());
            });
        }
    }
}
