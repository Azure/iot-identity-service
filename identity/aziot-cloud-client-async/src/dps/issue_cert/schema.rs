// Copyright (c) Microsoft. All rights reserved.

pub(crate) mod request {
    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct IssueCert {
        #[serde(rename = "certificateType")]
        pub cert_type: aziot_identity_common::CertType,

        pub csr: String,
    }
}

pub(crate) mod response {
    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct CertRequestStatus {
        pub status: super::RequestStatus,

        #[serde(rename = "resourceLocation")]
        pub uri: String,
    }

    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    pub(crate) struct Certificate {
        #[serde(rename = "issuedCertificate")]
        pub cert: String,

        #[serde(rename = "certificateChain")]
        pub chain: Vec<String>,
    }
}

impl std::convert::TryFrom<response::Certificate> for Vec<u8> {
    type Error = std::io::Error;

    fn try_from(response: response::Certificate) -> Result<Vec<u8>, std::io::Error> {
        // Parse and write out each certificate to check that it's valid and standardize
        // line endings.
        let cert = openssl::x509::X509::from_pem(response.cert.as_bytes()).map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to parse certificate: {}", err),
            )
        })?;

        let mut cert_stack = cert.to_pem().expect("parsed certificate should be valid");

        for cert in response.chain {
            let cert = openssl::x509::X509::from_pem(cert.as_bytes()).map_err(|err| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("failed to parse certificate: {}", err),
                )
            })?;

            let mut cert = cert.to_pem().expect("parsed certificate should be valid");

            cert_stack.append(&mut cert);
        }

        Ok(cert_stack)
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum RequestStatus {
    Unknown,
    NotStarted,
    Running,
    Failed,
    Succeeded,
}

impl std::fmt::Display for RequestStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestStatus::Unknown => f.write_str("unknown"),
            RequestStatus::NotStarted => f.write_str("notStarted"),
            RequestStatus::Running => f.write_str("running"),
            RequestStatus::Failed => f.write_str("failed"),
            RequestStatus::Succeeded => f.write_str("succeeded"),
        }
    }
}
