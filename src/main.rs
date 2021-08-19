use std::path::PathBuf;
use thiserror::Error;

use crate::certificate::read_certificates;

mod certificate;

#[derive(Debug, Error)]
enum Error {
    #[error("can not read certificate from file {1:?}: {0}")]
    ReadCertificate(certificate::ReadError, PathBuf),

    #[error("can not get entry from glob: {0}")]
    GlobError(glob::GlobError),
}

fn main() -> Result<(), Error> {
    let exporter =
        prometheus_exporter::start("0.0.0.0:9184".parse().expect("failed to parse binding"))
            .expect("failed to start prometheus exporter");

    loop {
        let guard = exporter.wait_request();

        let cert_glob =
            glob::glob("/tmp/tmp.br7CRPnXdv-tmpdir/*.crt").expect("failed to parse glob");

        let glob_entries = cert_glob
            .into_iter()
            .map(|entry| entry.map_err(Error::GlobError))
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
            .collect::<Vec<_>>();

        dbg!(certs);

        drop(guard);
    }
}
