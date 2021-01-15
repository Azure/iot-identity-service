// Copyright (c) Microsoft. All rights reserved.

#![allow(clippy::module_name_repetitions)]

pub mod authentication;
pub mod authorization;

/// Authenticated user types
#[derive(Clone, PartialOrd, PartialEq)]
pub enum AuthId {
    Unknown,

    HostProcess(aziot_identityd_config::Principal),

    Daemon,

    LocalRoot,
}

/// Operation types to be authorized
#[derive(Clone, PartialOrd, PartialEq)]
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
