// Copyright (c) Microsoft. All rights reserved.

//! A grab-bag of misc. utilities shared across the various sub-commands.

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use nix::unistd::{Uid, User};
use serde::Serialize;
use tokio::fs;
use tokio::io::AsyncReadExt;

#[derive(Debug, Serialize, Clone)]
pub struct CertificateValidity {
    pub(crate) cert_name: String,
    pub(crate) cert_id: String,
    pub(crate) not_after: chrono::DateTime<chrono::Utc>,
    pub(crate) not_before: chrono::DateTime<chrono::Utc>,
}

impl CertificateValidity {
    pub async fn new(
        cert_path: impl AsRef<Path>,
        cert_name: &str,
        cert_id: &str,
        aziotcs_user: &User,
    ) -> Result<CertificateValidity> {
        fn parse_openssl_time(
            time: &openssl::asn1::Asn1TimeRef,
        ) -> chrono::ParseResult<chrono::DateTime<chrono::Utc>> {
            // openssl::asn1::Asn1TimeRef does not expose any way to convert the ASN1_TIME to a Rust-friendly type
            //
            // Its Display impl uses ASN1_TIME_print, so we convert it into a String and parse it back
            // into a chrono::DateTime<chrono::Utc>
            let time = time.to_string();
            let time = chrono::NaiveDateTime::parse_from_str(&time, "%b %e %H:%M:%S %Y GMT")?;
            Ok(chrono::DateTime::<chrono::Utc>::from_utc(time, chrono::Utc))
        }

        let cert_path = cert_path.as_ref();

        aziotctl_common::config::check_readable(cert_path, aziotcs_user, false)?;

        let file_ctx = format!("operation on file {}", cert_path.display());

        let mut file = match fs::File::open(cert_path).await {
            Ok(f) => f,
            Err(e) => {
                return Err(e)
                    .context(file_ctx)
                    .context("Could not open cert file.")
            }
        };

        let mut pem = Vec::new();
        if let Err(e) = file.read_to_end(&mut pem).await {
            return Err(e)
                .context(file_ctx)
                .context("Could not read cert file.");
        }

        let cert = openssl::x509::X509::stack_from_pem(&pem)?;
        let cert = cert
            .get(0)
            .ok_or_else(|| anyhow!("could not parse {} as a valid .pem", cert_path.display()))?;

        let not_after = parse_openssl_time(cert.not_after())?;
        let not_before = parse_openssl_time(cert.not_before())?;

        Ok(CertificateValidity {
            cert_name: cert_name.to_string(),
            cert_id: cert_id.to_string(),
            not_after,
            not_before,
        })
    }
}

pub async fn resolve_and_tls_handshake(
    endpoint: hyper::Uri,
    hostname_display: &str,
    proxy_uri: Option<hyper::Uri>,
) -> Result<()> {
    use hyper::service::Service;

    // we don't actually care about the stream that gets returned. All we care about
    // is whether or not the TLS handshake was successful
    http_common::MaybeProxyConnector::new(proxy_uri, None, &[])
        .with_context(|| {
            anyhow!(
                "Could not connect to {} : could not create TLS connector",
                hostname_display,
            )
        })?
        .call(endpoint)
        .await
        .map_err(|e| anyhow!("{}", e))
        .with_context(|| {
            anyhow!(
                "Could not connect to {} : could not complete TLS handshake",
                hostname_display,
            )
        })?;

    Ok(())
}

pub(crate) fn get_system_user(name: &str) -> anyhow::Result<User> {
    if Uid::current().is_root() {
        Ok(User::from_name(name)
            .with_context(|| format!("could not query {} user information", name))?
            .ok_or_else(|| anyhow!("could not query {} user information", name))?)
    } else if cfg!(debug_assertions) {
        Ok(User::from_uid(Uid::current())
            .context("could not query current user information")?
            .ok_or_else(|| anyhow!("could not query current user information"))?)
    } else {
        Err(anyhow!("this command must be run as root"))
    }
}
