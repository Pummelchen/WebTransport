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

    let certified = rcgen::generate_simple_self_signed(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ])?;
    let cert_der = CertificateDer::from(certified.cert);
    let key_der: PrivateKeyDer<'static> =
        PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()).into();

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
