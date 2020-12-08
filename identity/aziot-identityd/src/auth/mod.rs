// Copyright (c) Microsoft. All rights reserved.

#![allow(clippy::module_name_repetitions)]

pub mod authentication;
pub mod authorization;

/// Authenticated user types
#[derive(Clone, PartialOrd, PartialEq)]
pub enum AuthId {
    Unknown,

    LocalPrincipal(Credentials),

    LocalRoot,
}

/// Operation types to be authorized
pub enum OperationType {
    GetModule(String),
    GetAllHubModules,
    GetDevice,
    CreateModule(String),
    DeleteModule(String),
    UpdateModule(String),
    ReprovisionDevice,
    GetTrustBundle,
}

/// Operation to be authorized
pub struct Operation {
    pub auth_id: AuthId,

    pub op_type: OperationType,
}

#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialOrd, PartialEq, serde::Deserialize, serde::Serialize,
)]
pub struct Uid(pub libc::uid_t);

pub type Credentials = Uid;
