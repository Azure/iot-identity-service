// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::default_trait_access,
    clippy::let_unit_value,
    clippy::too_many_lines,
    clippy::use_self
)]

#[tokio::main]
async fn main() -> Result<(), Error> {
    openssl::init();

    let command = structopt::StructOpt::from_args();

    match command {
        Command::GenerateCaCert {
            key_handle,
            out_file,
            subject,
        } => generate_cert(key_handle, &out_file, &subject, &GenerateCertKind::Ca)?,

        Command::GenerateClientCert {
            ca_cert,
            ca_key_handle,
            key_handle,
            out_file,
            subject,
        } => generate_cert(
            key_handle,
            &out_file,
            &subject,
            &GenerateCertKind::Client {
                ca_cert,
                ca_key_handle,
            },
        )?,

        Command::GenerateServerCert {
            ca_cert,
            ca_key_handle,
            key_handle,
            out_file,
            subject,
        } => generate_cert(
            key_handle,
            &out_file,
            &subject,
            &GenerateCertKind::Server {
                ca_cert,
                ca_key_handle,
            },
        )?,

        Command::WebClient {
            cert,
            key_handle,
            port,
        } => {
            let mut http_connector = hyper::client::HttpConnector::new();
            http_connector.enforce_http(false);

            let mut engine = load_engine()?;

            let key = load_private_key(&mut engine, key_handle)?;

            let mut tls_connector =
                openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls_client())?;
            tls_connector.set_private_key(&key)?;
            tls_connector.set_certificate_chain_file(&cert)?;

            // The root of the client cert is the CA, and we expect the server cert to be signed by this same CA.
            // So add it to the cert store.
            let ca_cert = {
                let cert_chain_file = std::fs::read(cert)?;
                let mut cert_chain = openssl::x509::X509::stack_from_pem(&cert_chain_file)?;
                cert_chain.pop().unwrap()
            };
            tls_connector.cert_store_mut().add_cert(ca_cert)?;

            // Log the server cert chain. Does not change the verification result from what openssl already concluded.
            tls_connector.set_verify_callback(
                openssl::ssl::SslVerifyMode::PEER,
                |openssl_verification_result, context| {
                    println!("Server cert:");
                    let chain = context.chain().unwrap();
                    for (i, cert) in chain.into_iter().enumerate() {
                        println!(
                            "    #{}: {}",
                            i + 1,
                            cert.subject_name()
                                .entries()
                                .next()
                                .unwrap()
                                .data()
                                .as_utf8()
                                .unwrap()
                        );
                    }
                    println!(
                        "openssl verification result: {}",
                        openssl_verification_result
                    );
                    openssl_verification_result
                },
            );

            let tls_connector =
                hyper_openssl::HttpsConnector::with_connector(http_connector, tls_connector)?;

            let client: hyper::Client<_, hyper::Body> =
                hyper::Client::builder().build(tls_connector);

            let response = client
                .get(format!("https://127.0.0.1:{}/", port).parse()?)
                .await?;

            let (http::response::Parts { status, .. }, response_body) = response.into_parts();
            let response_body = hyper::body::to_bytes(response_body).await?;

            println!("server returned {} {:?}", status, response_body);

            if status != http::StatusCode::OK || &*response_body != b"Hello, world!\n" {
                return Err("server did not return expected response".into());
            }
        }

        Command::WebServer {
            cert,
            key_handle,
            port,
        } => {
            let mut engine = load_engine()?;

            let key = load_private_key(&mut engine, key_handle)?;

            let incoming =
                test_common::tokio_openssl2::Incoming::new("0.0.0.0", port, &cert, &key, true)?;

            let server =
                hyper::Server::builder(incoming).serve(hyper::service::make_service_fn(|_| {
                    futures_util::future::ok::<_, std::convert::Infallible>(
                        hyper::service::service_fn(|_| {
                            futures_util::future::ok::<_, std::convert::Infallible>(
                                hyper::Response::new(hyper::Body::from("Hello, world!\n")),
                            )
                        }),
                    )
                }));

            println!("Starting web server...");

            let () = server.await?;
        }
    }

    Ok(())
}

fn load_engine() -> Result<openssl2::FunctionalEngine, Error> {
    const ENGINE_ID: &[u8] = b"aziot_keys\0";

    unsafe {
        openssl_sys2::ENGINE_load_builtin_engines();
    }

    let engine_id =
        std::ffi::CStr::from_bytes_with_nul(ENGINE_ID).expect("hard-coded engine ID is valid CStr");
    let engine = openssl2::StructuralEngine::by_id(engine_id)?;
    let engine: openssl2::FunctionalEngine = std::convert::TryInto::try_into(engine)?;
    println!("Loaded engine: [{}]", engine.name()?.to_string_lossy());
    Ok(engine)
}

fn load_public_key(
    engine: &mut openssl2::FunctionalEngine,
    key_handle: String,
) -> Result<openssl::pkey::PKey<openssl::pkey::Public>, Error> {
    let key_handle = std::ffi::CString::new(key_handle)?;
    let key = engine.load_public_key(&key_handle)?;
    Ok(key)
}

fn load_private_key(
    engine: &mut openssl2::FunctionalEngine,
    key_handle: String,
) -> Result<openssl::pkey::PKey<openssl::pkey::Private>, Error> {
    let key_handle = std::ffi::CString::new(key_handle)?;
    let key = engine.load_private_key(&key_handle)?;
    Ok(key)
}

fn generate_cert(
    key_handle: String,
    out_file: &std::path::Path,
    subject: &str,
    kind: &GenerateCertKind,
) -> Result<(), Error> {
    let mut engine = load_engine()?;

    let mut builder = openssl::x509::X509::builder()?;

    builder.set_version(2)?;

    let public_key = load_public_key(&mut engine, key_handle.clone())?;
    builder.set_pubkey(&public_key)?;

    let not_after = openssl::asn1::Asn1Time::days_from_now(match &kind {
        GenerateCertKind::Ca => 365,
        GenerateCertKind::Client { .. } | GenerateCertKind::Server { .. } => 30,
    })?;
    builder.set_not_after(std::borrow::Borrow::borrow(&not_after))?;

    let not_before = openssl::asn1::Asn1Time::days_from_now(0)?;
    builder.set_not_before(std::borrow::Borrow::borrow(&not_before))?;

    let mut subject_name = openssl::x509::X509Name::builder()?;
    subject_name.append_entry_by_text("CN", subject)?;
    let subject_name = subject_name.build();
    builder.set_subject_name(&subject_name)?;

    match &kind {
        GenerateCertKind::Ca => {
            builder.set_issuer_name(&subject_name)?;

            let ca_extension = openssl::x509::extension::BasicConstraints::new()
                .ca()
                .build()?;
            builder.append_extension(ca_extension)?;
        }

        GenerateCertKind::Client { ca_cert, .. } | GenerateCertKind::Server { ca_cert, .. } => {
            let ca_cert = std::fs::read(ca_cert)?;
            let ca_cert = openssl::x509::X509::from_pem(&ca_cert)?;
            builder.set_issuer_name(ca_cert.subject_name())?;

            match kind {
                GenerateCertKind::Ca => unreachable!(),

                GenerateCertKind::Client { .. } => {
                    let client_extension = openssl::x509::extension::ExtendedKeyUsage::new()
                        .client_auth()
                        .build()?;
                    builder.append_extension(client_extension)?;
                }

                GenerateCertKind::Server { .. } => {
                    let server_extension = openssl::x509::extension::ExtendedKeyUsage::new()
                        .server_auth()
                        .build()?;
                    builder.append_extension(server_extension)?;

                    let context = builder.x509v3_context(Some(&ca_cert), None);
                    let san_extension = openssl::x509::extension::SubjectAlternativeName::new()
                        .ip("127.0.0.1")
                        .build(&context)?;
                    builder.append_extension(san_extension)?;
                }
            }
        }
    }

    let ca_key_handle = match &kind {
        GenerateCertKind::Ca => key_handle,
        GenerateCertKind::Client { ca_key_handle, .. }
        | GenerateCertKind::Server { ca_key_handle, .. } => ca_key_handle.clone(),
    };
    let ca_key = load_private_key(&mut engine, ca_key_handle)?;
    builder.sign(&ca_key, openssl::hash::MessageDigest::sha256())?;

    let cert = builder.build();

    let cert = cert.to_pem()?;

    let mut out_file = std::fs::File::create(out_file)?;
    std::io::Write::write_all(&mut out_file, &cert)?;
    match &kind {
        GenerateCertKind::Ca => (),

        GenerateCertKind::Client { ca_cert, .. } | GenerateCertKind::Server { ca_cert, .. } => {
            let ca_cert = std::fs::read(ca_cert)?;
            std::io::Write::write_all(&mut out_file, &ca_cert)?;
        }
    }
    std::io::Write::flush(&mut out_file)?;

    Ok(())
}

#[derive(Debug)]
enum GenerateCertKind {
    Ca,
    Client {
        ca_cert: std::path::PathBuf,
        ca_key_handle: String,
    },
    Server {
        ca_cert: std::path::PathBuf,
        ca_key_handle: String,
    },
}

struct Error(Box<dyn std::error::Error>, backtrace::Backtrace);

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.0)?;

        let mut source = self.0.source();
        while let Some(err) = source {
            writeln!(f, "caused by: {}", err)?;
            source = err.source();
        }

        writeln!(f)?;

        writeln!(f, "{:?}", self.1)?;

        Ok(())
    }
}

impl<E> From<E> for Error
where
    E: Into<Box<dyn std::error::Error>>,
{
    fn from(err: E) -> Self {
        Error(err.into(), Default::default())
    }
}

#[derive(structopt::StructOpt)]
enum Command {
    /// Generate a CA cert.
    GenerateCaCert {
        /// A key handle to the key pair that will be used for the CA cert.
        #[structopt(long)]
        key_handle: String,

        /// The path where the CA cert PEM file will be stored.
        #[structopt(long)]
        out_file: std::path::PathBuf,

        /// The subject CN of the new cert.
        #[structopt(long)]
        subject: String,
    },

    /// Generate a client auth cert.
    GenerateClientCert {
        /// The path of the CA cert PEM file.
        #[structopt(long)]
        ca_cert: std::path::PathBuf,

        /// A key handle to the key pair of the CA.
        #[structopt(long)]
        ca_key_handle: String,

        /// A key handle to the key pair that will be used for the client cert.
        #[structopt(long)]
        key_handle: String,

        /// The path where the client cert PEM file will be stored.
        #[structopt(long)]
        out_file: std::path::PathBuf,

        /// The subject CN of the new cert.
        #[structopt(long)]
        subject: String,
    },

    /// Generate a server auth cert.
    GenerateServerCert {
        /// The path of the CA cert PEM file.
        #[structopt(long)]
        ca_cert: std::path::PathBuf,

        /// A key handle to the key pair of the CA.
        #[structopt(long)]
        ca_key_handle: String,

        /// A key handle to the key pair that will be used for the server cert.
        #[structopt(long)]
        key_handle: String,

        /// The path where the server cert PEM file will be stored.
        #[structopt(long)]
        out_file: std::path::PathBuf,

        /// The subject CN of the new cert.
        #[structopt(long)]
        subject: String,
    },

    /// Start a web client that uses the specified private key and cert file for TLS.
    WebClient {
        /// Path of the client cert file.
        #[structopt(long)]
        cert: std::path::PathBuf,

        /// A key handle to the client cert's key pair.
        #[structopt(long)]
        key_handle: String,

        /// The port to listen on.
        #[structopt(long, default_value = "8443")]
        port: u16,
    },

    /// Start a web server that uses the specified private key and cert file for TLS.
    WebServer {
        /// Path of the server cert file.
        #[structopt(long)]
        cert: std::path::PathBuf,

        /// A key handle to the server cert's key pair.
        #[structopt(long)]
        key_handle: String,

        /// The port to listen on.
        #[structopt(long, default_value = "8443")]
        port: u16,
    },
}
