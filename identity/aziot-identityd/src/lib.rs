// Copyright (c) Microsoft. All rights reserved.

pub mod app;
mod error;
mod logging;
pub mod settings;

pub use error::Error;

pub struct Server {}

impl Server {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Server {})
    }
}
