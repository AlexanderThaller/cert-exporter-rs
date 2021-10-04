use std::{
    collections::HashSet,
    path::PathBuf,
};
use structopt::{
    clap::AppSettings::{
        ColoredHelp,
        GlobalVersion,
        NextLineHelp,
        VersionlessSubcommands,
    },
    StructOpt,
};
use thiserror::Error;

use crate::{
    certificate,
    certificate::read_certificates,
    metrics,
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("can not read certificate from file {1:?}: {0}")]
    ReadCertificate(certificate::ReadError, PathBuf),

    #[error("can not get entry from glob: {0}")]
    Glob(glob::GlobError),

    #[error("can not start prometheus exporter: {0}")]
    StartPrometheusExporter(prometheus_exporter::Error),
}

#[derive(Debug, StructOpt)]
#[structopt(
    global_settings = &[ColoredHelp, VersionlessSubcommands, NextLineHelp, GlobalVersion]
)]
pub struct Opt {
    /// Where to read the certificates from as a glob. Example: /etc/ssl/*.crt
    #[structopt(short, long)]
    cert_glob: glob::Pattern,

    /// Log level to run under
    #[structopt(short,
                long,
                default_value = "info",
                possible_values = &["trace", "debug", "info", "warn", "error"])]
    pub log_level: log::LevelFilter,

    /// Address and port to expose the metrics to
    #[structopt(short, long, default_value = "127.0.0.1:9811")]
    pub binding: std::net::SocketAddr,
}

impl Opt {
    pub fn run(self) -> Result<(), Error> {
        if std::env::var_os("RUST_LOG").is_none() {
            std::env::set_var("RUST_LOG", self.log_level.as_str());
        }
        pretty_env_logger::init();

        let exporter =
            prometheus_exporter::start(self.binding).map_err(Error::StartPrometheusExporter)?;

        let mut metrics = metrics::new();

        loop {
            let guard = exporter.wait_request();

            let cert_glob = glob::glob(self.cert_glob.as_str())
                .expect("failed to parse glob. this should never happen");

            let glob_entries = cert_glob
                .into_iter()
                .map(|entry| entry.map_err(Error::Glob))
                .collect::<Result<Vec<_>, _>>()?;

            let certs = glob_entries
                .into_iter()
                .map(|path| read_certificates(&path).map_err(|e| Error::ReadCertificate(e, path)))
                .filter_map(|result| {
                    if let Err(ref err) = result {
                        eprintln!("{}", err);
                    };

                    result.ok()
                })
                .flatten()
                .collect::<HashSet<_>>();

            metrics.update(certs);

            drop(guard);
        }
    }
}
