use std::path::PathBuf;
use thiserror::Error;

use crate::certificate::read_certificates;

mod certificate;
use certificate::Certificate;

#[derive(Debug, Error)]
enum Error {
    #[error("can not read certificate from file {1:?}: {0}")]
    ReadCertificate(certificate::ReadError, PathBuf),

    #[error("can not get entry from glob: {0}")]
    GlobError(glob::GlobError),
}

fn main() -> Result<(), Error> {
    let cert_glob = glob::glob("/tmp/tmp.br7CRPnXdv-tmpdir/*.crt").expect("failed to parse glob");

    cert_glob
        .into_iter()
        .map(|entry| {
            entry
                .map(|path| read_certificates(&path).map_err(|e| Error::ReadCertificate(e, path)))
                .map_err(Error::GlobError)
        })
        .filter_map(|result| {
            match result {
                Err(err) => { eprintln!("{}", err); None }
                Ok(certificate) => Some(certificate),
            }
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(())
}
