// WebTransport echo server on web-transport-quiche (Cloudflare quiche stack).
//
// Modeled on the crate's own echo-server example, but generates its own
// self-signed certificate so the container needs no mounted key material.
// Streams only: the upstream example notes datagram support is not implemented,
// and the VPS matrix likewise runs quiche for the stream exchange alone.

use anyhow::{Context, Result};
use bytes::Bytes;
use web_transport_quiche::{CertificateDer, PrivateKeyDer, ServerBuilder};

#[tokio::main]
async fn main() -> Result<()> {
    let port: u16 = std::env::var("PORT").unwrap_or_else(|_| "54003".into()).parse()?;
    let bind: std::net::SocketAddr = format!("0.0.0.0:{port}").parse()?;

    // Load the CA-issued chain from disk. The point of this peer is that the
    // Swift client validates it with platform system trust, which a generated
    // self-signed certificate can never exercise.
    let cert_path = std::env::var("CERTFILE").expect("CERTFILE");
    let key_path = std::env::var("KEYFILE").expect("KEYFILE");
    let cert_pem = std::fs::read(&cert_path)?;
    let chain: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_slice()).collect::<Result<_, _>>()?;
    let key_pem = std::fs::read(&key_path)?;
    let key_der: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut key_pem.as_slice())?.expect("private key in KEYFILE");

    let mut server = ServerBuilder::default()
        .with_bind(bind)?
        .with_single_cert(chain, key_der)?;

    eprintln!("quiche echo server listening on {bind}");

    while let Some(request) = server.accept().await {
        tokio::spawn(async move {
            if let Err(error) = run_connection(request).await {
                eprintln!("connection closed: {error}");
            }
        });
    }
    Ok(())
}

async fn run_connection(request: web_transport_quiche::h3::Request) -> Result<()> {
    let session = request.ok().await.context("failed to accept session")?;
    eprintln!("session established");

    loop {
        let (mut send, mut recv) = session.accept_bi().await?;
        let mut message: Bytes = recv.read_all(64 * 1024).await?;
        eprintln!("stream in: {} bytes", message.len());
        send.write_buf_all(&mut message).await?;
        send.finish()?;
        eprintln!("stream echoed");
    }
}
