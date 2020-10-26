// Copyright (c) Microsoft. All rights reserved.

//! This binary is the process entrypoint for aziot-certd, -identityd and -keyd.
//! Rather than be three separate binaries, all three services are symlinks to
//! this one aziotd binary. The aziotd binary looks at its command-line args to figure out
//! which service it's being invoked as, and runs the code of that service accordingly.

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::default_trait_access, clippy::let_unit_value)]

mod error;
mod logging;

use error::{Error, ErrorKind};

#[tokio::main]
async fn main() {
    logging::init();

    if let Err(err) = main_inner().await {
        log::error!("{}", err.0);

        let mut source = std::error::Error::source(&err.0);
        while let Some(err) = source {
            log::error!("caused by: {}", err);
            source = std::error::Error::source(err);
        }

        log::error!("{:?}", err.1);

        std::process::exit(1);
    }
}

async fn main_inner() -> Result<(), Error> {
    let mut args = std::env::args_os();
    let process_name = process_name_from_args(&mut args)?;

    match process_name {
        ProcessName::Certd => {
            run(
                aziot_certd::main,
                "AZIOT_CERTD_CONFIG",
                "/etc/aziot/certd/config.toml",
                "AZIOT_CERTD_CONFIG_DIR",
                "/etc/aziot/certd/config.d",
            )
            .await?
        }

        ProcessName::Identityd => {
            run(
                aziot_identityd::main,
                "AZIOT_IDENTITYD_CONFIG",
                "/etc/aziot/identityd/config.toml",
                "AZIOT_IDENTITYD_CONFIG_DIR",
                "/etc/aziot/identityd/config.d",
            )
            .await?
        }

        ProcessName::Keyd => {
            run(
                aziot_keyd::main,
                "AZIOT_CERTD_CONFIG",
                "/etc/aziot/keyd/config.toml",
                "AZIOT_CERTD_CONFIG_DIR",
                "/etc/aziot/keyd/config.d",
            )
            .await?
        }
    }

    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum ProcessName {
    Certd,
    Identityd,
    Keyd,
}

/// If the symlink is being used to invoke this binary, the process name can be determined
/// from the first arg, ie `argv[0]` in C terms.
///
/// An alternative is supported where the binary is invoked as aziotd itself,
/// and the process name is instead the next arg, ie `argv[1]` in C terms.
/// This is primary useful for local development, so it's only allowed in debug builds.
fn process_name_from_args<I>(args: &mut I) -> Result<ProcessName, Error>
where
    I: Iterator,
    <I as Iterator>::Item: AsRef<std::ffi::OsStr>,
{
    let arg = args.next().ok_or_else(|| {
        ErrorKind::GetProcessName("could not extract process name from args".into())
    })?;

    // arg could be a single component like "aziot-certd", or a path that ends with "aziot-certd",
    // so parse it as a Path and get the last component. This does the right thing in either case.
    let arg = std::path::Path::new(&arg);
    let process_name = arg.file_name().ok_or_else(|| {
        ErrorKind::GetProcessName(
            format!(
                "could not extract process name from arg {:?}",
                arg.display(),
            )
            .into(),
        )
    })?;

    match process_name.to_str() {
        Some("aziot-certd") => Ok(ProcessName::Certd),

        Some("aziot-identityd") => Ok(ProcessName::Identityd),

        Some("aziot-keyd") => Ok(ProcessName::Keyd),

        // The next arg is the process name
        #[cfg(debug_assertions)]
        Some("aziotd") => process_name_from_args(args),

        _ => Err(ErrorKind::GetProcessName(
            format!("unrecognized process name {:?}", process_name).into(),
        )
        .into()),
    }
}

async fn run<TMain, TConfig, TFuture, TServer>(
    main: TMain,
    config_env_var: &str,
    config_file_default: &str,
    config_directory_env_var: &str,
    config_directory_default: &str,
) -> Result<(), Error>
where
    TMain: FnOnce(TConfig) -> TFuture,
    TConfig: serde::de::DeserializeOwned,
    TFuture: std::future::Future<
        Output = Result<(http_common::Connector, TServer), Box<dyn std::error::Error>>,
    >,
    TServer: hyper::service::Service<
            hyper::Request<hyper::Body>,
            Response = hyper::Response<hyper::Body>,
            Error = std::convert::Infallible,
        > + Clone
        + Send
        + 'static,
    <TServer as hyper::service::Service<hyper::Request<hyper::Body>>>::Future: Send,
{
    log::info!("Starting service...");
    log::info!(
        "Version - {}",
        option_env!("PACKAGE_VERSION").unwrap_or("dev build"),
    );

    let config_path: std::path::PathBuf =
        std::env::var_os(config_env_var).map_or_else(|| config_file_default.into(), Into::into);

    let config = std::fs::read(&config_path)
        .map_err(|err| ErrorKind::ReadConfig(Some(config_path.clone()), Box::new(err)))?;
    let mut config: toml::Value = toml::from_slice(&config)
        .map_err(|err| ErrorKind::ReadConfig(Some(config_path), Box::new(err)))?;

    let config_directory_path: std::path::PathBuf = std::env::var_os(config_directory_env_var)
        .map_or_else(|| config_directory_default.into(), Into::into);

    match std::fs::read_dir(&config_directory_path) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry.map_err(|err| {
                    ErrorKind::ReadConfig(Some(config_directory_path.clone()), Box::new(err))
                })?;

                let entry_file_type = entry.file_type().map_err(|err| {
                    ErrorKind::ReadConfig(Some(config_directory_path.clone()), Box::new(err))
                })?;
                if !entry_file_type.is_file() {
                    continue;
                }

                let patch_path = entry.path();
                if patch_path.extension().and_then(std::ffi::OsStr::to_str) != Some(".toml") {
                    continue;
                }

                let patch = std::fs::read(&patch_path).map_err(|err| {
                    ErrorKind::ReadConfig(Some(patch_path.clone()), Box::new(err))
                })?;
                let patch: toml::Value = toml::from_slice(&patch)
                    .map_err(|err| ErrorKind::ReadConfig(Some(patch_path), Box::new(err)))?;
                merge_toml(&mut config, patch);
            }
        }

        Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),

        Err(err) => {
            return Err(ErrorKind::ReadConfig(Some(config_directory_path), Box::new(err)).into())
        }
    }

    let config: TConfig = serde::Deserialize::deserialize(config)
        .map_err(|err| ErrorKind::ReadConfig(None, Box::new(err)))?;

    let (connector, server) = main(config).await.map_err(ErrorKind::Service)?;

    log::info!("Starting server...");

    let incoming = connector
        .incoming()
        .await
        .map_err(|err| ErrorKind::Service(Box::new(err)))?;
    let server = hyper::Server::builder(incoming).serve(hyper::service::make_service_fn(|_| {
        let server = server.clone();
        async move { Ok::<_, std::convert::Infallible>(server.clone()) }
    }));
    let () = server
        .await
        .map_err(|err| ErrorKind::Service(Box::new(err)))?;

    log::info!("Stopped server.");

    Ok(())
}

fn merge_toml(base: &mut toml::Value, patch: toml::Value) {
    // Similar to JSON patch, except that maps are called tables, and
    // there is no equivalent of null that can be used to remove keys from an object.

    if let toml::Value::Table(base) = base {
        if let toml::Value::Table(patch) = patch {
            for (key, value) in patch {
                // Insert a dummy `false` if the original key didn't exist at all. It'll be overwritten by `value` in that case.
                let original_value = base.entry(key).or_insert(toml::Value::Boolean(false));
                merge_toml(original_value, value);
            }

            return;
        }
    }

    *base = patch;
}

#[cfg(test)]
mod tests {
    #[test]
    fn process_name_from_args() {
        for &(input, expected) in &[
            (&["aziot-certd"][..], super::ProcessName::Certd),
            (&["aziot-identityd"][..], super::ProcessName::Identityd),
            (&["aziot-keyd"][..], super::ProcessName::Keyd),
            (
                &["/usr/libexec/aziot/aziot-certd"][..],
                super::ProcessName::Certd,
            ),
            (
                &["/usr/libexec/aziot/aziot-identityd"][..],
                super::ProcessName::Identityd,
            ),
            (
                &["/usr/libexec/aziot/aziot-keyd"][..],
                super::ProcessName::Keyd,
            ),
            (&["aziotd", "aziot-certd"][..], super::ProcessName::Certd),
            (
                &["aziotd", "aziot-identityd"][..],
                super::ProcessName::Identityd,
            ),
            (&["aziotd", "aziot-keyd"][..], super::ProcessName::Keyd),
            (
                &["/usr/libexec/aziot/aziotd", "aziot-certd"][..],
                super::ProcessName::Certd,
            ),
            (
                &["/usr/libexec/aziot/aziotd", "aziot-identityd"][..],
                super::ProcessName::Identityd,
            ),
            (
                &["/usr/libexec/aziot/aziotd", "aziot-keyd"][..],
                super::ProcessName::Keyd,
            ),
        ] {
            let mut input = input.iter().copied().map(std::ffi::OsStr::new);
            let actual = super::process_name_from_args(&mut input).unwrap();
            assert_eq!(None, input.next());
            assert_eq!(expected, actual);
        }

        for &input in &[
            &["foo"][..],
            &["/usr/libexec/aziot/foo"][..],
            &["aziotd", "foo"][..],
            &["/usr/libexec/aziot/aziotd", "foo"][..],
            &["/usr/libexec/aziot/foo", "aziot-certd"][..],
        ] {
            let mut input = input.iter().copied().map(std::ffi::OsStr::new);
            let _ = super::process_name_from_args(&mut input).unwrap_err();
        }
    }

    #[test]
    fn merge_toml() {
        let base = r#"
foo_key = "A"
foo_parent_key = { foo_sub_key = "B" }

[bar_table]
bar_table_key = "C"
bar_table_parent_key = { bar_table_sub_key = "D" }

[[baz_table_array]]
baz_table_array_key = "E"
baz_table_array_parent_key = { baz_table_sub_key = "F" }
"#;
        let mut base: toml::Value = toml::from_str(base).unwrap();

        let patch = r#"
foo_key = "A2"
foo_key_new = "A3"
foo_parent_key = { foo_sub_key = "B2", foo_sub_key2 = "B3" }
foo_parent_key_new = { foo_sub_key = "B4", foo_sub_key2 = "B5" }

[bar_table]
bar_table_key = "C2"
bar_table_key_new = "C3"
bar_table_parent_key = { bar_table_sub_key = "D2", bar_table_sub_key2 = "D3" }
bar_table_parent_key_new = { bar_table_sub_key = "D4", bar_table_sub_key2 = "D5" }

[[baz_table_array]]
baz_table_array_key = "G"
baz_table_array_parent_key = { baz_table_sub_key = "H" }
"#;
        let patch: toml::Value = toml::from_str(patch).unwrap();

        super::merge_toml(&mut base, patch);

        let expected = r#"
foo_key = "A2"
foo_key_new = "A3"
foo_parent_key = { foo_sub_key = "B2", foo_sub_key2 = "B3" }
foo_parent_key_new = { foo_sub_key = "B4", foo_sub_key2 = "B5" }


[bar_table]
bar_table_key = "C2"
bar_table_key_new = "C3"
bar_table_parent_key = { bar_table_sub_key = "D2", bar_table_sub_key2 = "D3" }
bar_table_parent_key_new = { bar_table_sub_key = "D4", bar_table_sub_key2 = "D5" }

[[baz_table_array]]
baz_table_array_key = "G"
baz_table_array_parent_key = { baz_table_sub_key = "H" }
"#;
        let expected: toml::Value = toml::from_str(expected).unwrap();
        assert_eq!(expected, base);
    }
}
