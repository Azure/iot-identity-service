use crate::PreloadedCert;

pub fn get_path(
    homedir_path: &std::path::Path,
    preloaded_certs: &std::collections::BTreeMap<String, PreloadedCert>,
    cert_id: &str,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(preloaded_cert) = preloaded_certs.get(cert_id) {
        let path = get_preloaded_cert_path(preloaded_cert, cert_id)?;
        return Ok(path);
    }

    let mut path = homedir_path.to_owned();
    path.push("certs");

    if !path.exists() {
        let () = std::fs::create_dir_all(&path)?;
    }

    let id_sanitized: String = cert_id
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect();

    let hash = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), cert_id.as_bytes())?;
    let hash = hex::encode(hash);
    path.push(format!("{}-{}.cer", id_sanitized, hash));

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
                    "preloaded cert {:?} does not have a valid URI: unrecognized scheme {:?}",
                    cert_id, scheme,
                )
                .into());
            }

            let path = uri.to_file_path().map_err(|()| {
                format!(
                    "preloaded cert {:?} does not have a valid URI: not a valid path",
                    cert_id,
                )
            })?;

            Ok(path)
        }

        PreloadedCert::Ids(_) => Err(format!(
            "preloaded cert {:?} is a list of IDs, not a single URI",
            cert_id,
        )
        .into()),
    }
}
