use chrono::NaiveDateTime;
use std::{
    convert::{
        TryFrom,
        TryInto,
    },
    path::Path,
};
use thiserror::Error;
use x509_parser::{
    certificate::X509Certificate,
    pem::Pem,
};

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct Certificate {
    pub subject: String,
    pub issuer: String,

    pub common_names: Vec<String>,

    pub not_before: NaiveDateTime,
    pub not_after: NaiveDateTime,
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("can not parse common names: {0}")]
    ParseCommonNames(der_parser::error::BerError),
}

#[derive(Debug, Error)]
pub enum ReadError {
    #[error("can not open certificate file: {0}")]
    OpenCertificateFile(std::io::Error),

    #[error("can not parse pem from file: {0}")]
    ParsePEM(x509_parser::prelude::PEMError),

    #[error("can not parse x509 from pem: {0}")]
    ParseX509(x509_parser::nom::Err<x509_parser::error::X509Error>),

    #[error("can not parse certificate from x509: {0}")]
    ParseCertificate(ParseError),
}

impl TryFrom<X509Certificate<'_>> for Certificate {
    type Error = ParseError;

    fn try_from(x509: X509Certificate<'_>) -> Result<Self, Self::Error> {
        let subject = x509.subject().to_string();
        let issuer = x509.issuer().to_string();

        let common_names = x509
            .subject()
            .iter_common_name()
            .map(|entry| entry.attr_value().as_str().map(|s| s.to_string()))
            .collect::<Result<_, _>>()
            .map_err(ParseError::ParseCommonNames)?;

        let not_before = NaiveDateTime::from_timestamp(x509.validity().not_before.timestamp(), 0);
        let not_after = NaiveDateTime::from_timestamp(x509.validity().not_after.timestamp(), 0);

        Ok(Self {
            subject,
            issuer,
            common_names,
            not_before,
            not_after,
        })
    }
}

pub fn read_certificates(path: impl AsRef<Path>) -> Result<Vec<Certificate>, ReadError> {
    let data = std::fs::read(path).map_err(ReadError::OpenCertificateFile)?;

    let pems = Pem::iter_from_buffer(&data)
        .map(|pem| pem.map_err(ReadError::ParsePEM))
        .collect::<Result<Vec<_>, _>>()?;

    let x509 = pems
        .iter()
        .map(|pem| pem.parse_x509().map_err(ReadError::ParseX509))
        .collect::<Result<Vec<_>, _>>()?;

    let certificates = x509
        .into_iter()
        .map(|x509| x509.try_into().map_err(ReadError::ParseCertificate))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(certificates)
}
