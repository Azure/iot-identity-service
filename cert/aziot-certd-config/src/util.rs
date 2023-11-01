// Copyright (c) Microsoft. All rights reserved.

use crate::PreloadedCert;

/// `create_dir_if_not_exist` should only be set to true when this method is
/// called from `aziot-certd`, or else the directory may be created with the
/// incorrect permissions.
pub fn get_path(
    homedir_path: &std::path::Path,
    preloaded_certs: &std::collections::BTreeMap<String, PreloadedCert>,
    cert_id: &str,
    create_dir_if_not_exist: bool,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(preloaded_cert) = preloaded_certs.get(cert_id) {
        let path = get_preloaded_cert_path(preloaded_cert, cert_id)?;
        return Ok(path);
    }

    let mut path = homedir_path.to_owned();
    path.push("certs");

    if !path.exists() && create_dir_if_not_exist {
        let () = std::fs::create_dir_all(&path)?;
    }

    let id_sanitized: String = cert_id
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect();

    let hash = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), cert_id.as_bytes())?;
    let hash = hex::encode(hash);
    path.push(format!("{id_sanitized}-{hash}.cer"));

    Ok(path)
}

fn get_preloaded_cert_path(
    preloaded_cert: &PreloadedCert,
    cert_id: &str,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    match preloaded_cert {
        PreloadedCert::Uri(uri) => {
            let scheme = uri.scheme();
            if scheme != "file" {
                return Err(format!(
                    "preloaded cert {cert_id:?} does not have a valid URI: unrecognized scheme {scheme:?}",
                )
                .into());
            }

            let path = uri.to_file_path().map_err(|()| {
                format!(
                    "preloaded cert {cert_id:?} does not have a valid URI: not a valid path",
                )
            })?;

            Ok(path)
        }

        PreloadedCert::Ids(_) => Err(format!(
            "preloaded cert {cert_id:?} is a list of IDs, not a single URI",
        )
        .into()),
    }
}
