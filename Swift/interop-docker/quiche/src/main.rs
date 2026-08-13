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

    let certified = rcgen::generate_simple_self_signed(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ])?;
    let chain: Vec<CertificateDer<'static>> = vec![CertificateDer::from(certified.cert)];
    let key: PrivateKeyDer<'static> =
        PrivateKeyDer::try_from(certified.key_pair.serialize_der())
            .map_err(|error| anyhow::anyhow!("private key rejected: {error}"))?;

    let mut server = ServerBuilder::default()
        .with_bind(bind)?
        .with_single_cert(chain, key)?;

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
