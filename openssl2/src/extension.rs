// Copyright (c) Microsoft. All rights reserved.

/// Extended Key Usage.
#[derive(Debug)]
pub struct ExtKeyUsage {
    /// Server authentication.
    server_auth: bool,
    // extKeyUsage contains other fields, but only serverAuth is used in Certs Service.
    // Unused other fields are omitted.
}

impl ExtKeyUsage {
    /// Parse an extension as `extKeyUsage`.
    pub fn from_ext(ext: &openssl::x509::X509Extension) -> Option<Self> {
        let (name, data) = parse_extension(ext);

        if name != openssl::nid::Nid::EXT_KEY_USAGE {
            return None;
        }

        let objects = {
            // extKeyUsage should contain a single ASN.1 sequence.
            let sequence = simple_asn1::from_der(data.as_slice()).ok()?.pop()?;

            if let simple_asn1::ASN1Block::Sequence(_, objects) = sequence {
                objects
            } else {
                return None;
            }
        };

        let mut ext_key_usage = ExtKeyUsage { server_auth: false };

        // Parse through the list of OIDs, setting the corresponding flags as they are found.
        // Relevant OIDs to parse from extKeyUsage are in group 1.3.6.1.5.5.7.3.
        // See https://oidref.com/1.3.6.1.5.5.7.3 for a list of extKeyUsage OIDs.
        for obj in objects {
            if let simple_asn1::ASN1Block::ObjectIdentifier(_, oid) = obj {
                // OID 1.3.6.1.5.5.7.3.1 => id-kp-serverAuth
                if oid == simple_asn1::oid!(1, 3, 6, 1, 5, 5, 7, 3, 1) {
                    ext_key_usage.server_auth = true;
                }
            } else {
                return None;
            }
        }

        Some(ext_key_usage)
    }

    /// Check if this `extKeyUsage` has serverAuth set.
    pub fn server_auth(&self) -> bool {
        self.server_auth
    }
}

fn parse_extension(
    ext: &openssl::x509::X509Extension,
) -> (openssl::nid::Nid, &openssl::asn1::Asn1BitStringRef) {
    let (obj, data): (openssl::asn1::Asn1Object, _) = unsafe {
        let ptr = foreign_types_shared::ForeignType::as_ptr(ext);

        let obj = openssl_sys2::X509_EXTENSION_get_object(ptr);
        let data = openssl_sys2::X509_EXTENSION_get_data(ptr);

        (
            foreign_types_shared::ForeignType::from_ptr(obj),
            foreign_types_shared::ForeignTypeRef::from_ptr(data),
        )
    };

    (obj.nid(), data)
}

#[cfg(test)]
mod tests {
    use super::ExtKeyUsage;

    #[test]
    fn server_auth() {
        // extKeyUsage = serverAuth
        let ext_key_usage = openssl::x509::extension::ExtendedKeyUsage::new()
            .server_auth()
            .build()
            .unwrap();

        let extension = ExtKeyUsage::from_ext(&ext_key_usage).unwrap();
        assert!(extension.server_auth());

        // extKeyUsage = critical, serverAuth
        let ext_key_usage = openssl::x509::extension::ExtendedKeyUsage::new()
            .critical()
            .server_auth()
            .build()
            .unwrap();

        let extension = ExtKeyUsage::from_ext(&ext_key_usage).unwrap();
        assert!(extension.server_auth());

        // extKeyUsage = clientAuth, serverAuth, codeSigning, emailProtection
        let ext_key_usage = openssl::x509::extension::ExtendedKeyUsage::new()
            .client_auth()
            .server_auth()
            .code_signing()
            .email_protection()
            .build()
            .unwrap();

        let extension = ExtKeyUsage::from_ext(&ext_key_usage).unwrap();
        assert!(extension.server_auth());

        // extKeyUsage = clientAuth, codeSigning, emailProtection
        let ext_key_usage = openssl::x509::extension::ExtendedKeyUsage::new()
            .client_auth()
            .code_signing()
            .email_protection()
            .build()
            .unwrap();

        let extension = ExtKeyUsage::from_ext(&ext_key_usage).unwrap();
        assert!(!extension.server_auth());
    }
}
