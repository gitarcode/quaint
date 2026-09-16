use super::{SslAcceptMode, SslParams};
use crate::error::{Error, ErrorKind};
use p12_keystore::{KeyStore, Pkcs12ImportPolicy};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{self, CryptoProvider},
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use std::{fs, io::Cursor, sync::Arc};
use tokio_postgres_rustls::MakeRustlsConnect;

fn tls_error(error: impl std::fmt::Display) -> Error {
    Error::builder(ErrorKind::TlsError {
        message: error.to_string(),
    })
    .build()
}

pub(super) fn connector(params: &SslParams) -> crate::Result<MakeRustlsConnect> {
    // Do not depend on another SDK installing a process-default provider first.
    let provider = Arc::new(crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    roots.add_parsable_certificates(native.certs);
    for error in native.errors {
        tracing::warn!("Could not load a system TLS certificate: {error}");
    }

    if let Some(path) = &params.certificate_file {
        let pem = fs::read(path).map_err(|error| tls_error(format!("cert file not found ({error})")))?;
        let certs = rustls_pemfile::certs(&mut Cursor::new(pem))
            .collect::<Result<Vec<_>, _>>()
            .map_err(tls_error)?;
        if certs.is_empty() {
            return Err(tls_error("certificate file contains no PEM certificates"));
        }
        for cert in certs {
            roots.add(cert).map_err(tls_error)?;
        }
    }

    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(tls_error)?
        .with_root_certificates(roots);

    let mut config = if let Some(path) = &params.identity_file {
        let der = fs::read(path).map_err(|error| tls_error(format!("identity file not found ({error})")))?;
        let password = params.identity_password.0.as_deref().unwrap_or("");
        let store = KeyStore::from_pkcs12(&der, password, Pkcs12ImportPolicy::Strict).map_err(tls_error)?;
        let (_, identity) = store
            .private_key_chain()
            .ok_or_else(|| tls_error("PKCS#12 identity contains no private key and certificate chain"))?;
        let chain = identity
            .certs()
            .iter()
            .map(|cert| CertificateDer::from(cert.as_der().to_vec()))
            .collect();
        let key = PrivatePkcs8KeyDer::from(identity.key().as_der().to_vec());
        builder.with_client_auth_cert(chain, key.into()).map_err(tls_error)?
    } else {
        builder.with_no_client_auth()
    };

    // Preserve the existing opt-in/default Quaint acceptance policy. Handshake
    // signatures still prove possession of the peer certificate's private key.
    if params.ssl_accept_mode == SslAcceptMode::AcceptInvalidCerts {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(AcceptInvalidCertificates { provider }));
    }

    Ok(MakeRustlsConnect::new(config))
}

#[derive(Debug)]
struct AcceptInvalidCertificates {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for AcceptInvalidCertificates {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        crypto::verify_tls12_signature(
            message,
            cert,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        crypto::verify_tls13_signature(
            message,
            cert,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}
