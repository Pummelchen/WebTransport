// WebTransport echo peer on web-transport-quinn, for the VPS interop matrix.
//
// Presents a CA-issued certificate loaded from disk rather than a generated
// self-signed one. That is the whole point of this peer: it lets the Swift
// client validate with platform system trust over a routable network path,
// which a loopback self-signed peer can never exercise.

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
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

    let cert_path = std::env::var("CERTFILE").context("CERTFILE not set")?;
    let key_path = std::env::var("KEYFILE").context("KEYFILE not set")?;
    let cert_pem = std::fs::read(&cert_path).context("reading CERTFILE")?;
    let chain: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_slice()).collect::<Result<_, _>>()?;
    let key_pem = std::fs::read(&key_path).context("reading KEYFILE")?;
    let key_der: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut key_pem.as_slice())?.context("no private key in KEYFILE")?;

    let mut server = ServerBuilder::new()
        .with_addr(addr)
        .with_certificate(chain, key_der)?;

    eprintln!("quinn echo listening on {addr} with {cert_path}");

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
                }
            });

            let streams = tokio::spawn(async move {
                while let Ok((mut send, mut recv)) = session.accept_bi().await {
                    match recv.read_to_end(64 * 1024).await {
                        Ok(data) => {
                            eprintln!("stream in: {} bytes", data.len());
                            let _ = send.write_all(&data).await;
                            let _ = send.finish();
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
