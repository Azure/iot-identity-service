use super::{ProvisioningType, Settings};

impl Settings {
    pub fn check(self) -> Result<Self, std::io::Error> {
        let mut existing_names: std::collections::BTreeSet<aziot_identity_common::ModuleId> =
            std::collections::BTreeSet::default();

        for p in &self.principal {
            if !existing_names.insert(p.name.clone()) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("duplicate module name: {}", p.name.0),
                ));
            }

            if let Some(t) = &p.id_type {
                if t.contains(&aziot_identity_common::IdType::Local) {
                    // Require localid in config if any principal has local id_type.
                    if self.localid.is_none() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!(
                                "invalid config for {}: local id type requires localid config",
                                p.name.0
                            ),
                        ));
                    }
                } else {
                    // Reject principals that specify local identity options without the "local" type.
                    if p.localid.is_some() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!("invalid config for {}: local identity options specified for non-local identity", p.name.0)
                        ));
                    }
                }

                // Require provisioning if any module or device identities are present.
                let provisioning_valid = match self.provisioning.provisioning {
                    ProvisioningType::None => {
                        !t.contains(&aziot_identity_common::IdType::Module)
                            && !t.contains(&aziot_identity_common::IdType::Device)
                    }
                    _ => true,
                };

                if !provisioning_valid {
                    return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!("invalid config for {}: module or device identity requires provisioning with IoT Hub", p.name.0)
                        )
                    );
                }
            }
        }

        Ok(self)
    }
}
