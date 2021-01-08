// Copyright (c) Microsoft. All rights reserved.

//! This binary is the process entrypoint for aziot-certd, -identityd and -keyd.
//! Rather than be three separate binaries, all three services are symlinks to
//! this one aziotd binary. The aziotd binary looks at its command-line args to figure out
//! which service it's being invoked as, and runs the code of that service accordingly.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
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
                "AZIOT_KEYD_CONFIG",
                "/etc/aziot/keyd/config.toml",
                "AZIOT_KEYD_CONFIG_DIR",
                "/etc/aziot/keyd/config.d",
            )
            .await?
        }

        ProcessName::Tpmd => {
            run(
                aziot_tpmd::main,
                "AZIOT_TPMD_CONFIG",
                "/etc/aziot/tpmd/config.toml",
                "AZIOT_TPMD_CONFIG_DIR",
                "/etc/aziot/tpmd/config.d",
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
    Tpmd,
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
        Some("aziot-tpmd") => Ok(ProcessName::Tpmd),

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
    TMain: FnOnce(TConfig, std::path::PathBuf, std::path::PathBuf) -> TFuture,
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

    let config_directory_path: std::path::PathBuf = std::env::var_os(config_directory_env_var)
        .map_or_else(|| config_directory_default.into(), Into::into);

    let config: TConfig = config_common::read_config(config_path.clone(), config_directory_path.clone()).map_err(|err| ErrorKind::ReadConfig(err))?;

    let (connector, server) = main(config, config_path, config_directory_path).await.map_err(ErrorKind::Service)?;

    log::info!("Starting server...");

    let mut incoming = connector
        .incoming()
        .await
        .map_err(|err| ErrorKind::Service(Box::new(err)))?;
    let () = incoming
        .serve(server)
        .await
        .map_err(|err| ErrorKind::Service(Box::new(err)))?;

    log::info!("Stopped server.");
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn process_name_from_args() {
        // Success test cases
        let mut test_cases = vec![
            (&["aziot-certd"][..], super::ProcessName::Certd),
            (&["aziot-identityd"][..], super::ProcessName::Identityd),
            (&["aziot-keyd"][..], super::ProcessName::Keyd),
            (&["aziot-tpmd"][..], super::ProcessName::Tpmd),
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
            (
                &["/usr/libexec/aziot/aziot-tpmd"][..],
                super::ProcessName::Tpmd,
            ),
        ];

        // argv[1] fallback is only in release builds.
        if cfg!(debug_assertions) {
            test_cases.extend_from_slice(&[
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
                (
                    &["/usr/libexec/aziot/aziotd", "aziot-tpmd"][..],
                    super::ProcessName::Tpmd,
                ),
            ]);
        }

        for (input, expected) in test_cases {
            let mut input = input.iter().copied().map(std::ffi::OsStr::new);
            let actual = super::process_name_from_args(&mut input).unwrap();
            assert_eq!(None, input.next());
            assert_eq!(expected, actual);
        }

        // Failure test cases
        for &input in &[
            // Unrecognized process name in argv[0]
            &["foo"][..],
            &["/usr/libexec/aziot/foo"][..],
            &["/usr/libexec/aziot/foo", "aziot-certd"][..],
            // Either fails because it's a release build so argv[1] fallback is disabled,
            // or fails because it's a debug build where argv[1] fallback is enabled
            // but the process name in argv[1] is unrecognized anyway.
            &["aziotd", "foo"][..],
            &["/usr/libexec/aziot/aziotd", "foo"][..],
        ] {
            let mut input = input.iter().copied().map(std::ffi::OsStr::new);
            let _ = super::process_name_from_args(&mut input).unwrap_err();
        }
    }
}
