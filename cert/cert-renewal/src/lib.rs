// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::missing_panics_doc)]

pub mod lifetime;

pub use lifetime::Lifetime;
