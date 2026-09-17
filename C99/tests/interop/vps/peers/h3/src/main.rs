// WebTransport datagram echo built on hyperium/h3 + h3-webtransport.
//
// Mirrors the other VPS peers: PORT, CERTFILE and KEYFILE come from the
// environment, and the certificate is a real one so the Swift client can connect
// with system trust over a routable path.

use anyhow::{Context, Result};
use bytes::Bytes;
use h3::server::Connection;
use h3_webtransport::server::WebTransportSession;
use http::Method;
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install rustls ring provider");

    let port: u16 = std::env::var("PORT").unwrap_or_else(|_| "54005".into()).parse()?;
    let addr: std::net::SocketAddr = format!("0.0.0.0:{port}").parse()?;

    let cert_path = std::env::var("CERTFILE").context("CERTFILE not set")?;
    let key_path = std::env::var("KEYFILE").context("KEYFILE not set")?;
    let cert_pem = std::fs::read(&cert_path).context("reading CERTFILE")?;
    let chain: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_slice()).collect::<Result<_, _>>()?;
    let key_pem = std::fs::read(&key_path).context("reading KEYFILE")?;
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut key_pem.as_slice())?.context("no private key in KEYFILE")?;

    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    // WebTransport rides on HTTP/3, so h3 is the only protocol worth offering.
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let mut transport = quinn::TransportConfig::default();
    // Datagrams are the whole point of this peer.
    transport.datagram_receive_buffer_size(Some(65536));
    transport.datagram_send_buffer_size(65536);

    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    server_config.transport = Arc::new(transport);

    let endpoint = quinn::Endpoint::server(server_config, addr)?;
    eprintln!("h3-webtransport echo listening on {addr} with {cert_path}");

    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            if let Err(error) = serve(incoming).await {
                eprintln!("connection ended: {error}");
            }
        });
    }
    Ok(())
}

async fn serve(incoming: quinn::Incoming) -> Result<()> {
    let connection = incoming.await?;
    eprintln!("quic connection established");

    let mut h3_connection: Connection<h3_quinn::Connection, Bytes> = h3::server::builder()
        .enable_webtransport(true)
        .enable_extended_connect(true)
        .enable_datagram(true)
        .max_webtransport_sessions(1)
        .send_grease(true)
        .build(h3_quinn::Connection::new(connection))
        .await?;

    match h3_connection.accept().await {
        Ok(Some(resolver)) => {
            let (request, stream) = resolver.resolve_request().await?;
            if request.method() != Method::CONNECT {
                eprintln!("ignoring non-CONNECT request");
                return Ok(());
            }
            let session = WebTransportSession::accept(request, stream, h3_connection).await?;
            eprintln!("webtransport session established");

            // The sender is already bound to the CONNECT stream, so it frames
            // each payload with the session id on the way out.
            let mut reader = session.datagram_reader();
            let mut sender = session.datagram_sender();
            loop {
                match reader.read_datagram().await {
                    Ok(datagram) => {
                        let payload = datagram.into_payload();
                        eprintln!("datagram in: {} bytes", payload.len());
                        if let Err(error) = sender.send_datagram(payload) {
                            eprintln!("send failed: {error}");
                            break;
                        }
                    }
                    Err(error) => {
                        eprintln!("datagram read ended: {error}");
                        break;
                    }
                }
            }
        }
        Ok(None) => eprintln!("connection closed before a request arrived"),
        Err(error) => eprintln!("accept failed: {error}"),
    }
    Ok(())
}
