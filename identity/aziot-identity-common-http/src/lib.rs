// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ApiVersion {
    V2020_09_01,
    V2021_12_01,
    V2022_08_01,
}

impl std::fmt::Display for ApiVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ApiVersion::V2020_09_01 => "2020-09-01",
            ApiVersion::V2021_12_01 => "2021-12-01",
            ApiVersion::V2022_08_01 => "2022-08-01",
        })
    }
}

impl std::str::FromStr for ApiVersion {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "2020-09-01" => Ok(ApiVersion::V2020_09_01),
            "2021-12-01" => Ok(ApiVersion::V2021_12_01),
            "2022-08-01" => Ok(ApiVersion::V2022_08_01),
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
    pub struct Request {
        #[serde(rename = "type")]
        pub id_type: String,
        #[serde(rename = "moduleId")]
        pub module_id: String,
    }

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

pub mod get_provisioning_info {
    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    #[serde(tag = "source", rename_all = "lowercase")]
    pub enum Response {
        Dps {
            auth: String,
            endpoint: String,
            scope_id: String,
            registration_id: String,

            #[serde(skip_serializing_if = "Option::is_none")]
            cert_policy: Option<aziot_identity_common::CertPolicy>,

            payload: Option<serde_json::Value>,
        },
        Manual {
            auth: String,
        },
        None,
    }
}
