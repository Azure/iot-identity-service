// Copyright (c) Microsoft. All rights reserved.

/// Basic Constraints
///
/// See [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9)
/// for more information.
pub struct BasicConstraints {
    pub ca: bool,
}

impl BasicConstraints {
    pub fn from_ext(ext: &openssl::x509::X509ExtensionRef) -> Option<Self> {
        let (name, data) = parse_extension(ext);

        if name != openssl::nid::Nid::BASIC_CONSTRAINTS {
            return None;
        }

        let objects = if let Ok(mut blocks) = simple_asn1::from_der(data.as_slice()) {
            let sequence = blocks.pop()?;

            if let simple_asn1::ASN1Block::Sequence(_, objects) = sequence {
                objects
            } else {
                return None;
            }
        } else {
            // Empty basicConstraints is equivalent to CA:FALSE.
            return Some(BasicConstraints { ca: false });
        };

        let mut ca = false;

        for object in objects {
            if let simple_asn1::ASN1Block::Boolean(id, value) = object {
                if id == 2 {
                    ca = value;
                }
            }
        }

        Some(BasicConstraints { ca })
    }
}

fn parse_extension(
    ext: &openssl::x509::X509ExtensionRef,
) -> (openssl::nid::Nid, &openssl::asn1::Asn1BitStringRef) {
    let (obj, data): (&openssl::asn1::Asn1ObjectRef, _) = unsafe {
        let ptr = foreign_types_shared::ForeignTypeRef::as_ptr(ext);

        let obj = openssl_sys2::X509_EXTENSION_get_object(ptr);
        let data = openssl_sys2::X509_EXTENSION_get_data(ptr);

        (
            foreign_types_shared::ForeignTypeRef::from_ptr(obj),
            foreign_types_shared::ForeignTypeRef::from_ptr(data),
        )
    };

    (obj.nid(), data)
}

#[cfg(test)]
mod tests {
    use super::BasicConstraints;

    #[test]
    fn ca() {
        // basicConstraints = critical, CA:TRUE, pathlen=2
        let basic_constraints = openssl::x509::extension::BasicConstraints::new()
            .critical()
            .ca()
            .pathlen(2)
            .build()
            .unwrap();

        let extension = BasicConstraints::from_ext(&basic_constraints).unwrap();
        assert!(extension.ca);

        // basicConstraints = empty
        let basic_constraints = openssl::x509::extension::BasicConstraints::new()
            .build()
            .unwrap();

        let extension = BasicConstraints::from_ext(&basic_constraints).unwrap();
        assert!(!extension.ca);

        // basicConstraints = critical
        let basic_constraints = openssl::x509::extension::BasicConstraints::new()
            .critical()
            .build()
            .unwrap();

        let extension = BasicConstraints::from_ext(&basic_constraints).unwrap();
        assert!(!extension.ca);
    }
}
