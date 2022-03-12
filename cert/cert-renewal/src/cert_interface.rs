// Copyright (c) Microsoft. All rights reserved.

#[async_trait::async_trait]
pub trait CertInterface {
    type GetContext;

    async fn get(
        context: &mut Self::GetContext,
        cert_id: &str,
    ) -> Result<openssl::x509::X509, std::io::Error>;
}
