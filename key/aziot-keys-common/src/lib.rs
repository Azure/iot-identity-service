// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]

/// This crate exists to hold any types that need to be shared between aziot-keys and the other crates,
/// so that aziot-keys does not have to be compiled as an rlib.
///
/// This is because anything that triggers aziot-keys to be compiled as an rlib triggers
/// <https://github.com/rust-lang/cargo/issues/6313>, specifically:
///
/// >`panic="abort"` and cdylibs and tests: Create a project with a lib (cdylib crate type), binary, and an integration test,
/// >with panic="abort" in the profile. When `cargo test` runs, the cdylib is built twice (once with panic=abort for the binary,
/// >and once without for the test), with the same filename. Building the lib for the test should probably skip the `cdylib` crate type
/// >(assuming rlib is also available), but implementing this is very difficult.
///
/// What this bug means for us is that `make test` recompiles aziot-keys every time even if it hasn't changed,
/// because `cargo build` and `cargo test` keep marking the build dirty for each other.

#[derive(Clone, Debug)]
pub enum PreloadedKeyLocation {
    Filesystem { path: std::path::PathBuf },
    Pkcs11 { uri: pkcs11::Uri },
}

impl std::fmt::Display for PreloadedKeyLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PreloadedKeyLocation::Filesystem { path } => write!(
                f,
                "{}",
                url::Url::from_file_path(path).map_err(|_e| std::fmt::Error)?
            ),
            PreloadedKeyLocation::Pkcs11 { uri } => uri.fmt(f),
        }
    }
}

impl std::str::FromStr for PreloadedKeyLocation {
    type Err = Box<dyn std::error::Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let scheme_end_index = s.find(':').ok_or("missing scheme")?;
        let scheme = &s[..scheme_end_index];

        match scheme {
            "file" => {
                let uri: url::Url = s.parse()?;
                let path = uri
                    .to_file_path()
                    .map_err(|()| "cannot convert to file path")?;
                Ok(PreloadedKeyLocation::Filesystem { path })
            }

            "pkcs11" => {
                let uri = s.parse()?;
                Ok(PreloadedKeyLocation::Pkcs11 { uri })
            }

            _ => Err("unrecognized scheme".into()),
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PreloadedKeyLocation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = PreloadedKeyLocation;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("preloaded key location URI")
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                s.parse().map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for PreloadedKeyLocation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = self.to_string();
        serializer.serialize_str(&s)
    }
}
