// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
    clippy::default_trait_access,
    clippy::let_unit_value,
    clippy::too_many_lines,
    clippy::use_self
)]

mod tokio_openssl2;

#[tokio::main]
async fn main() -> Result<(), Error> {
    openssl::init();

    let Options {
        pkcs11_lib_path,
        pkcs11_spy_path,
        command,
    } = structopt::StructOpt::from_args();

    #[allow(clippy::option_if_let_else)]
    // Side-effects in a combinator closure are not a good thing.
    let pkcs11_lib_path = if let Some(pkcs11_spy_path) = pkcs11_spy_path {
        std::env::set_var("PKCS11SPY", &pkcs11_lib_path);
        pkcs11_spy_path
    } else {
        pkcs11_lib_path
    };

    match command {
        Command::GenerateCaCert {
            key,
            out_file,
            subject,
        } => generate_cert(
            pkcs11_lib_path,
            key,
            &out_file,
            &subject,
            &GenerateCertKind::Ca,
        )?,

        Command::GenerateClientCert {
            ca_cert,
            ca_key,
            key,
            out_file,
            subject,
        } => generate_cert(
            pkcs11_lib_path,
            key,
            &out_file,
            &subject,
            &GenerateCertKind::Client { ca_cert, ca_key },
        )?,

        Command::GenerateKeyPair { key, r#type } => {
            let key: pkcs11::Uri = key.parse()?;

            let pkcs11_context = load_pkcs11_context(pkcs11_lib_path)?;

            let pkcs11_slot = pkcs11_context.find_slot(&key.slot_identifier)?;

            let pkcs11_session = pkcs11_context.open_session(pkcs11_slot, key.pin)?;

            match r#type {
                KeyType::Ec(curve) => {
                    let (public_key_handle, _) = pkcs11_session.generate_ec_key_pair(
                        curve,
                        key.object_label.as_ref().map(AsRef::as_ref),
                    )?;
                    let public_key_parameters = public_key_handle.parameters()?;
                    let public_key_parameters = Displayable(public_key_parameters);
                    println!("Created EC key with parameters {}", public_key_parameters);
                }

                KeyType::Rsa(modulus_bits) => {
                    let exponent = openssl_sys::RSA_F4;
                    let exponent = exponent.to_be_bytes();
                    let exponent = openssl::bn::BigNum::from_slice(&exponent)?;

                    let (public_key_handle, _) = pkcs11_session.generate_rsa_key_pair(
                        modulus_bits,
                        &exponent,
                        key.object_label.as_ref().map(AsRef::as_ref),
                    )?;
                    let public_key_parameters = public_key_handle.parameters()?;
                    let public_key_parameters = Displayable(public_key_parameters);
                    println!("Created RSA key with parameters {}", public_key_parameters);
                }
            }
        }

        Command::GenerateServerCert {
            ca_cert,
            ca_key,
            key,
            out_file,
            subject,
        } => generate_cert(
            pkcs11_lib_path,
            key,
            &out_file,
            &subject,
            &GenerateCertKind::Server {
                hostname: "example.com",
                ca_cert,
                ca_key,
            },
        )?,

        Command::Load { keys } => {
            let pkcs11_context = load_pkcs11_context(pkcs11_lib_path)?;

            let mut engine = load_engine(pkcs11_context)?;

            for key in keys {
                let key = load_public_key(&mut engine, key)?;

                if let Ok(ec_key) = key.ec_key() {
                    let ec_key = Displayable(ec_key);
                    println!("Loaded EC key with parameters {}", ec_key);
                } else if let Ok(rsa) = key.rsa() {
                    let rsa = Displayable(rsa);
                    println!("Loaded RSA key with parameters {}", rsa);
                }
            }
        }

        Command::WebClient { cert, key, port } => {
            let pkcs11_context = load_pkcs11_context(pkcs11_lib_path)?;

            let mut engine = load_engine(pkcs11_context)?;

            let key = load_private_key(&mut engine, key)?;

            let stream = std::net::TcpStream::connect(&("127.0.0.1", port))?;
            let response_body = tokio_openssl2::connect(stream, &cert, &key, "example.com").await?;
            println!("Server responded with {:?}", response_body);
        }

        Command::WebServer { cert, key, port } => {
            let pkcs11_context = load_pkcs11_context(pkcs11_lib_path)?;

            let mut engine = load_engine(pkcs11_context)?;

            let key = load_private_key(&mut engine, key)?;

            let listener = std::net::TcpListener::bind(&("0.0.0.0", port))?;
            let incoming = tokio_openssl2::Incoming::new(listener, &cert, &key)?;

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

fn load_pkcs11_context(
    pkcs11_lib_path: std::path::PathBuf,
) -> Result<std::sync::Arc<pkcs11::Context>, Error> {
    let pkcs11_context = pkcs11::Context::load(pkcs11_lib_path)?;
    if let Some(info) = pkcs11_context.info() {
        println!("Loaded PKCS#11 library: {}", info);
    } else {
        println!("Loaded PKCS#11 library: <unknown>");
    }

    Ok(pkcs11_context)
}

fn load_engine(
    pkcs11_context: std::sync::Arc<pkcs11::Context>,
) -> Result<openssl2::FunctionalEngine, Error> {
    let engine = pkcs11_openssl_engine::load(pkcs11_context)?;
    println!("Loaded engine: [{}]", engine.name()?.to_string_lossy());
    Ok(engine)
}

fn load_public_key(
    engine: &mut openssl2::FunctionalEngine,
    key_id: String,
) -> Result<openssl::pkey::PKey<openssl::pkey::Public>, Error> {
    let key_id = std::ffi::CString::new(key_id)?;
    let key = engine.load_public_key(&key_id)?;
    Ok(key)
}

fn load_private_key(
    engine: &mut openssl2::FunctionalEngine,
    key_id: String,
) -> Result<openssl::pkey::PKey<openssl::pkey::Private>, Error> {
    let key_id = std::ffi::CString::new(key_id)?;
    let key = engine.load_private_key(&key_id)?;
    Ok(key)
}

fn generate_cert(
    pkcs11_lib_path: std::path::PathBuf,
    key: String,
    out_file: &std::path::Path,
    subject: &str,
    kind: &GenerateCertKind,
) -> Result<(), Error> {
    let pkcs11_context = load_pkcs11_context(pkcs11_lib_path)?;

    let mut engine = load_engine(pkcs11_context)?;

    let mut builder = openssl::x509::X509::builder()?;

    builder.set_version(2)?;

    let public_key = load_public_key(&mut engine, key.clone())?;
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

                GenerateCertKind::Server { hostname, .. } => {
                    let server_extension = openssl::x509::extension::ExtendedKeyUsage::new()
                        .server_auth()
                        .build()?;
                    builder.append_extension(server_extension)?;

                    let context = builder.x509v3_context(Some(&ca_cert), None);
                    let san_extension = openssl::x509::extension::SubjectAlternativeName::new()
                        .dns(hostname)
                        .build(&context)?;
                    builder.append_extension(san_extension)?;
                }
            }
        }
    }

    let ca_key = match &kind {
        GenerateCertKind::Ca => key,
        GenerateCertKind::Client { ca_key, .. } | GenerateCertKind::Server { ca_key, .. } => {
            ca_key.to_owned()
        }
    };
    let ca_key = load_private_key(&mut engine, ca_key)?;
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
        ca_key: String,
    },
    Server {
        hostname: &'static str,
        ca_cert: std::path::PathBuf,
        ca_key: String,
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
struct Options {
    /// Path of the PKCS#11 library.
    #[structopt(env = "PKCS11_LIB_PATH", long)]
    pkcs11_lib_path: std::path::PathBuf,

    /// If set to the path of the OpenSC PKCS#11 Spy library, the spy library will be used to wrap around
    /// the actual PKCS#11 library specified by `--pkcs11-lib-path`
    #[structopt(env = "PKCS11_SPY_PATH", long)]
    pkcs11_spy_path: Option<std::path::PathBuf>,

    #[structopt(subcommand)]
    command: Command,
}

#[derive(structopt::StructOpt)]
enum Command {
    /// Generate a CA cert.
    GenerateCaCert {
        /// The ID of the key pair of the CA, in a PKCS#11 URI format.
        #[structopt(long)]
        key: String,

        /// The path where the CA cert PEM file will be stored.
        #[structopt(long)]
        out_file: std::path::PathBuf,

        /// The subject CN of the new cert.
        #[structopt(long)]
        subject: String,
    },

    /// Generate a client auth cert.
    GenerateClientCert {
        #[structopt(long)]
        ca_cert: std::path::PathBuf,

        /// The ID of the key pair of the CA, in PKCS#11 URI format.
        #[structopt(long)]
        ca_key: String,

        /// The ID of the key pair of the client requesting the cert, in PKCS#11 URI format.
        #[structopt(long)]
        key: String,

        /// The path where the client cert PEM file will be stored.
        #[structopt(long)]
        out_file: std::path::PathBuf,

        /// The subject CN of the new cert.
        #[structopt(long)]
        subject: String,
    },

    /// Generate a key pair in the HSM.
    GenerateKeyPair {
        /// The ID of the token where the key pair will be stored, in a PKCS#11 URI format.
        ///
        /// Must have either a `token` (label) or `slot-id` (slot ID) component to identify the slot,
        /// and a `pin-value` (user PIN) component.
        #[structopt(long)]
        key: String,

        /// The type of key pair to generate.
        #[structopt(long)]
        #[structopt(possible_values = KEY_TYPE_VALUES)]
        r#type: KeyType,
    },

    /// Generate a server auth cert.
    GenerateServerCert {
        #[structopt(long)]
        ca_cert: std::path::PathBuf,

        /// The ID of the key pair of the CA, in PKCS#11 URI format.
        #[structopt(long)]
        ca_key: String,

        /// The ID of the key pair of the server requesting the cert, in PKCS#11 URI format.
        #[structopt(long)]
        key: String,

        /// The path where the server cert PEM file will be stored.
        #[structopt(long)]
        out_file: std::path::PathBuf,

        /// The subject CN of the new cert.
        #[structopt(long)]
        subject: String,
    },

    /// Load one or more public keys from the HSM.
    Load {
        /// One or more IDs of public keys, each in PKCS#11 URI format. Each argument to the command is one key ID.
        #[structopt(long)]
        keys: Vec<String>,
    },

    /// Connect to a web server with a client that uses the specified private key and cert file for TLS client auth.
    WebClient {
        /// Path of the cert chain file.
        #[structopt(long)]
        cert: std::path::PathBuf,

        /// The ID of the key pair corresponding to the cert, in PKCS#11 URI format.
        #[structopt(long)]
        key: String,

        /// The port to connect to.
        #[structopt(long, default_value = "8443")]
        port: u16,
    },

    /// Start a web server that uses the specified private key and cert file for TLS.
    WebServer {
        /// Path of the cert chain file.
        #[structopt(long)]
        cert: std::path::PathBuf,

        /// The ID of the key pair corresponding to the cert, in PKCS#11 URI format.
        #[structopt(long)]
        key: String,

        /// The port to listen on.
        #[structopt(long, default_value = "8443")]
        port: u16,
    },
}

const KEY_TYPE_VALUES: &[&str] = &[
    "ec-p256",
    "ec-p384",
    "ec-p521",
    #[cfg(ossl111)]
    "ec-ed25519",
    "rsa-2048",
    "rsa-4096",
];

enum KeyType {
    Ec(openssl2::EcCurve),
    Rsa(pkcs11_sys::CK_ULONG),
}

impl std::str::FromStr for KeyType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ec-p256" => Ok(KeyType::Ec(openssl2::EcCurve::NistP256)),
            "ec-p384" => Ok(KeyType::Ec(openssl2::EcCurve::NistP384)),
            "ec-p521" => Ok(KeyType::Ec(openssl2::EcCurve::NistP521)),
            #[cfg(ossl111)]
            "ec-ed25519" => Ok(KeyType::Ec(openssl2::EcCurve::Ed25519)),
            "rsa-2048" => Ok(KeyType::Rsa(2048)),
            "rsa-4096" => Ok(KeyType::Rsa(4096)),
            s => Err(format!("unrecognized value [{}]", s)),
        }
    }
}

struct Displayable<T>(T);

impl<T> std::fmt::Display for Displayable<openssl::ec::EcKey<T>>
where
    T: openssl::pkey::HasPublic,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let group = self.0.group();
        let curve_name = group
            .curve_name()
            .map(|nid| nid.long_name())
            .transpose()?
            .unwrap_or("<unknown>");

        let mut big_num_context = openssl::bn::BigNumContext::new()?;
        let point = self.0.public_key();
        let point = point.to_bytes(
            group,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut big_num_context,
        )?;

        write!(f, "curve = {}, point = 0x", curve_name)?;
        for b in point {
            write!(f, "{:02x}", b)?;
        }

        Ok(())
    }
}

impl<T> std::fmt::Display for Displayable<openssl::rsa::Rsa<T>>
where
    T: openssl::pkey::HasPublic,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let modulus = self.0.n();

        let exponent = self.0.e();

        write!(
            f,
            "modulus = 0x{} ({} bits), exponent = {}",
            modulus.to_hex_str()?,
            modulus.num_bits(),
            exponent
        )?;

        Ok(())
    }
}
