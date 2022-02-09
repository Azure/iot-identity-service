// Copyright (c) Microsoft. All rights reserved.

mod register;
pub use register::Register;

mod server_cert;
pub use server_cert::ServerCert;

pub mod schema;

const API_VERSION: &str = "api-version=2021-11-01-preview";
