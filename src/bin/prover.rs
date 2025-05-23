use std::net::{IpAddr, SocketAddr};

use http_body_util::Empty;
use hyper::{Request, StatusCode, Uri, body::Bytes};

use hyper_util::rt::TokioIo;
use tls_core::verify::WebPkiVerifier;
use tlsn_common::config::ProtocolConfig;
use tlsn_core::{CryptoProvider, transcript::Idx};
use tlsn_prover::{Prover, ProverConfig, state::Prove};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::Level;

const MAX_SENT_DATA: usize = 1 << 12;
const MAX_RECV_DATA: usize = 1 << 14;

const SECRET: &str = "TLSNotary's private key 🤡";
const SERVER_DOMAIN: &str = "localhost";
const SERVER_PORT: u16 = 3001;

const SERVER_ADDR: &str = "127.0.0.1";
const VERIFIER_ADDR: &str = "127.0.0.1:8079";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::fmt()
        .with_max_level(Level::DEBUG)
        .init();

    let uri = format!(
        "https://{}:{}/retail/transaction/6",
        SERVER_DOMAIN, SERVER_PORT
    );
    let server_ip: IpAddr = SERVER_ADDR.parse().expect("Invalid IP address");
    let server_addr = SocketAddr::new(server_ip, SERVER_PORT);

    let verifier_socket = TcpStream::connect(VERIFIER_ADDR).await.unwrap();

    prover(verifier_socket, &server_addr, &uri).await;
}

async fn prover<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    verifier_socket: T,
    server_addr: &SocketAddr,
    uri: &str,
) {
    let uri = uri.parse::<Uri>().unwrap();
    println!("URI: {:?}", uri);
    assert_eq!(uri.scheme().unwrap().as_str(), "https");

    let server_domain = uri.authority().unwrap().host();
    println!("Server domain: {}", server_domain);

    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(
            include_bytes!("../../certs/rootCA.der").to_vec(),
        ))
        .unwrap();
    let crypto_provider = CryptoProvider {
        cert: WebPkiVerifier::new(root_store, None),
        ..Default::default()
    };

    let prover = Prover::new(
        ProverConfig::builder()
            .server_name(server_domain)
            .protocol_config(
                ProtocolConfig::builder()
                    .max_sent_data(MAX_SENT_DATA)
                    .max_recv_data(MAX_RECV_DATA)
                    .build()
                    .unwrap(),
            )
            .crypto_provider(crypto_provider)
            .build()
            .unwrap(),
    )
    .setup(verifier_socket.compat())
    .await
    .unwrap();

    // Connect to TLS Server.
    let tls_client_socket = TcpStream::connect(server_addr).await.unwrap();
    println!("Connected to TLS Server");

    // Pass server connection into the prover.
    let (mpc_tls_connection, prover_fut) =
        prover.connect(tls_client_socket.compat()).await.unwrap();
    println!("Connected to Verifier");

    // Wrap the connection in a TokioIo compatibility layer to use it with hyper.
    let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());
    println!("Wrapped connection in FuturesIo compatibility layer");

    // Spawn the Prover to run in the background.
    let prover_task = tokio::spawn(prover_fut);
    println!("Spawned the Prover to run in the background");

    // MPC-TLS Handshake.
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(mpc_tls_connection)
            .await
            .unwrap();
    println!("Handshake completed");

    // Spawn the connection to run in the background.
    tokio::spawn(connection);
    println!("Spawned the connection to run in the background");

    let request = Request::builder()
        .uri(uri.clone())
        .header("Host", server_domain)
        .header("Connection", "close")
        .header("Secret", SECRET)
        .method("GET")
        .body(Empty::<Bytes>::new())
        .unwrap();
    println!("Request {:?}", request);
    let response = request_sender.send_request(request).await.unwrap();
    println!("Request sent");

    assert!(response.status() == StatusCode::OK);
    println!("Response received");

    let mut prover = prover_task.await.unwrap().unwrap().start_prove();
    println!("Started the Prover");
    // Reveal parts of the transcript.
    let idx_sent = revealed_ranges_sent(&mut prover);
    println!("Revealed ranges for sent data");
    let idx_recv = revealed_ranges_received(&mut prover);
    println!("Revealed ranges for received data");
    prover.prove_transcript(idx_sent, idx_recv).await.unwrap();
    println!("Proved the transcript");
    prover.finalize().await.unwrap();
    println!("Finalized the prover");
}

/// Returns the received ranges to be revealed to the verifier.
fn revealed_ranges_received(prover: &mut Prover<Prove>) -> Idx {
    let recv_transcript = prover.transcript().received();
    let recv_transcript_len = recv_transcript.len();

    Idx::new([0..recv_transcript_len])
}

/// Returns the sent ranges to be revealed to the verifier.
fn revealed_ranges_sent(prover: &mut Prover<Prove>) -> Idx {
    let sent_transcript = prover.transcript().sent();
    let sent_transcript_len = sent_transcript.len();

    // Reveal everything except for the SECRET.
    Idx::new([0..sent_transcript_len])
}
