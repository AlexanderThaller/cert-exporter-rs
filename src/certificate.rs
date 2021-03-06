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

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Certificate {
    pub subject: String,
    pub issuer: String,

    pub common_names: Vec<String>,

    pub time_to_expiration: time::Duration,
    pub not_before: NaiveDateTime,
    pub not_after: NaiveDateTime,
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("can not parse common names: {0}")]
    ParseCommonNames(x509_parser::der_parser::error::Error),
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
            .map(|entry| entry.attr_value().as_str().map(ToString::to_string))
            .collect::<Result<_, _>>()
            .map_err(ParseError::ParseCommonNames)?;

        let validity = x509.validity();
        let time_to_expiration = validity.time_to_expiration().unwrap_or_default();
        let not_before = NaiveDateTime::from_timestamp(validity.not_before.timestamp(), 0);
        let not_after = NaiveDateTime::from_timestamp(validity.not_after.timestamp(), 0);

        Ok(Self {
            subject,
            issuer,
            common_names,
            time_to_expiration,
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
        .filter(|pem| pem.label == "CERTIFICATE")
        .map(|pem| pem.parse_x509().map_err(ReadError::ParseX509))
        .collect::<Result<Vec<_>, _>>()?;

    let certificates = x509
        .into_iter()
        .map(|x509| x509.try_into().map_err(ReadError::ParseCertificate))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(certificates)
}

#[cfg(test)]
mod test {
    use chrono::{
        NaiveDate,
        NaiveDateTime,
        NaiveTime,
    };
    use pretty_assertions::assert_eq;
    use time::Duration;

    use super::Certificate;

    #[test]
    fn read_certificate_file() {
        let mut expected = vec![Certificate {
            subject: "C=TE, ST=Test-State, L=Test-City, O=Test-Organisation, OU=Test-Section, \
                      CN=example.net, Email=test@example.net"
                .into(),
            issuer: "C=TE, ST=Test-State, L=Test-City, O=Test-Organisation, OU=Test-Section, \
                     CN=example.net, Email=test@example.net"
                .into(),
            common_names: vec!["example.net".into()],
            time_to_expiration: Duration::nanoseconds(0),
            not_before: NaiveDateTime::new(
                NaiveDate::from_ymd(2021, 08, 18),
                NaiveTime::from_hms(09, 38, 11),
            ),
            not_after: NaiveDateTime::new(
                NaiveDate::from_ymd(2022, 08, 18),
                NaiveTime::from_hms(09, 38, 11),
            ),
        }];

        let got = super::read_certificates("resources/test.crt").unwrap();

        // Dynamic value can not test that so easily
        expected[0].time_to_expiration = got[0].time_to_expiration;

        assert_eq!(expected, got);
    }

    #[test]
    fn read_pem_file() {
        let mut expected = vec![Certificate {
            subject: "C=AU, ST=Some-State, O=Internet Widgits Pty Ltd".into(),
            issuer: "C=AU, ST=Some-State, O=Internet Widgits Pty Ltd".into(),
            common_names: vec![],
            time_to_expiration: Duration::new(31535150, 464404684),
            not_before: NaiveDateTime::new(
                NaiveDate::from_ymd(2022, 04, 20),
                NaiveTime::from_hms(12, 37, 01),
            ),
            not_after: NaiveDateTime::new(
                NaiveDate::from_ymd(2023, 04, 20),
                NaiveTime::from_hms(12, 37, 01),
            ),
        }];

        let got = super::read_certificates("resources/test.pem").unwrap();

        // Dynamic value can not test that so easily
        expected[0].time_to_expiration = got[0].time_to_expiration;

        assert_eq!(expected, got);
    }
}
