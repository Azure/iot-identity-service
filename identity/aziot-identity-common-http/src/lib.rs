// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ApiVersion {
    V2020_09_01,
    V2020_12_10,
}

impl std::fmt::Display for ApiVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ApiVersion::V2020_09_01 => "2020-09-01",
            ApiVersion::V2020_12_10 => "2020-12-10",
        })
    }
}

impl std::str::FromStr for ApiVersion {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "2020-09-01" => Ok(ApiVersion::V2020_09_01),
            "2020-12-10" => Ok(ApiVersion::V2020_12_10),
            _ => Err(()),
        }
    }
}

pub mod get_caller_identity {
    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    pub struct Response {
        #[serde(flatten)]
        pub identity: aziot_identity_common::Identity,
    }
}

pub mod get_device_identity {
    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    pub struct Request {
        #[serde(rename = "type")]
        pub id_type: String,
    }

    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    pub struct Response {
        #[serde(flatten)]
        pub identity: aziot_identity_common::Identity,
    }
}

pub mod create_module_identity {
    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    pub enum CreateModuleOpts {
        LocalIdOpts(aziot_identity_common::LocalIdOpts),
    }

    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    pub struct Request {
        #[serde(rename = "type")]
        pub id_type: String,
        #[serde(rename = "moduleId")]
        pub module_id: String,
        #[serde(flatten)]
        pub opts: Option<CreateModuleOpts>,
    }

    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    pub struct Response {
        #[serde(flatten)]
        pub identity: aziot_identity_common::Identity,
    }
}

pub mod update_module_identity {
    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    pub struct Response {
        #[serde(flatten)]
        pub identity: aziot_identity_common::Identity,
    }
}

pub mod get_module_identities {
    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    pub struct Response {
        pub identities: Vec<aziot_identity_common::Identity>,
    }
}

pub mod get_module_identity {
    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    pub struct Response {
        #[serde(flatten)]
        pub identity: aziot_identity_common::Identity,
    }
}

pub mod get_trust_bundle {
    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    pub struct Response {
        pub certificate: aziot_cert_common_http::Pem,
    }
}

pub mod reprovision_device {
    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    pub struct Request {
        #[serde(rename = "type")]
        pub id_type: String,
    }
}

pub mod get_aad_identity {
    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    pub struct Request {
        pub tenant: String,
        pub scope: String,
        pub aad_id: String,
    }

    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    pub struct Response {
        pub token: String,
    }
}
