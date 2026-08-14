// WebTransport echo server on web-transport-quinn.
//
// Stands in for the third-party Rust/quinn peer in the interop matrix so the
// Swift client can be validated against an independent implementation locally.
// Echoes bidirectional stream payloads and datagrams back verbatim.

use anyhow::Result;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use web_transport_quinn::ServerBuilder;

#[tokio::main]
async fn main() -> Result<()> {
    // Both ring and aws-lc-rs can be pulled in transitively, so the default
    // provider must be chosen explicitly or rustls panics at first use.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install rustls ring provider");

    let port: u16 = std::env::var("PORT").unwrap_or_else(|_| "54002".into()).parse()?;
    let addr: std::net::SocketAddr = format!("0.0.0.0:{port}").parse()?;

    // Browsers accept a self-signed certificate via serverCertificateHashes only
    // when it is ECDSA P-256 with a validity window under 14 days, so the
    // lifetime is set explicitly rather than taking rcgen's multi-year default.
    let mut params = rcgen::CertificateParams::new(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ])?;
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(7);
    let key_pair = rcgen::KeyPair::generate()?;
    let certificate = params.self_signed(&key_pair)?;

    let cert_der = CertificateDer::from(certificate.der().to_vec());
    let key_der: PrivateKeyDer<'static> =
        PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into();

    {
        use sha2::{Digest, Sha256};
        use base64::Engine;
        let digest = Sha256::digest(cert_der.as_ref());
        eprintln!(
            "certificate-sha256: {}",
            base64::engine::general_purpose::STANDARD.encode(digest)
        );
    }

    let mut server = ServerBuilder::new()
        .with_addr(addr)
        .with_certificate(vec![cert_der], key_der)?;

    eprintln!("quinn echo server listening on {addr}");

    while let Some(request) = server.accept().await {
        tokio::spawn(async move {
            let session = match request.ok().await {
                Ok(session) => session,
                Err(error) => {
                    eprintln!("accept failed: {error}");
                    return;
                }
            };
            eprintln!("session established");

            let datagram_session = session.clone();
            let datagrams = tokio::spawn(async move {
                while let Ok(payload) = datagram_session.read_datagram().await {
                    eprintln!("datagram in: {} bytes", payload.len());
                    if datagram_session.send_datagram(payload).is_err() {
                        break;
                    }
                    eprintln!("datagram echoed");
                }
            });

            let streams = tokio::spawn(async move {
                while let Ok((mut send, mut recv)) = session.accept_bi().await {
                    match recv.read_to_end(64 * 1024).await {
                        Ok(data) => {
                            eprintln!("stream in: {} bytes", data.len());
                            let _ = send.write_all(&data).await;
                            let _ = send.finish();
                            eprintln!("stream echoed");
                        }
                        Err(error) => eprintln!("stream read failed: {error}"),
                    }
                }
            });

            let _ = tokio::join!(datagrams, streams);
        });
    }
    Ok(())
}
