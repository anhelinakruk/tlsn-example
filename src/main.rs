use std::net::{IpAddr, SocketAddr};

use http_body_util::Empty;
use hyper::{Request, StatusCode, Uri, body::Bytes};
use macro_rules_attribute::apply;
use smol::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    spawn,
};
use smol_hyper::rt::FuturesIo;
use smol_macros::main;
use tls_core::verify::WebPkiVerifier;
use tlsn_common::config::{ProtocolConfig, ProtocolConfigValidator};
use tlsn_core::CryptoProvider;
use tlsn_prover::{Prover, ProverConfig};
use tlsn_verifier::{SessionInfo, Verifier, VerifierConfig};

const SECRET: &str = "TLSNotary's private key 🤡";
const SERVER_DOMAIN: &str = "test-server.io";
#[apply(main!)]
async fn main() {
    tracing_subscriber::fmt::init();

    let server_port: u16 = 4000;

    let uri = format!("https://{}:{}/formats/html", SERVER_DOMAIN, server_port);
    let server_ip: IpAddr = "127.0.0.1".parse().expect("Invalid IP address");
    let server_addr = SocketAddr::new(server_ip, server_port);

    let listener = TcpListener::bind("127.0.0.1:8079").await.unwrap();
    let verifier_addr = listener.local_addr().unwrap();

    let verifier_task = spawn(async move {
        let (verifier_stream, _) = listener.accept().await.unwrap();
        verifier(verifier_stream).await
    });

    let prover_socket = TcpStream::connect(verifier_addr).await.unwrap();
    let prover_task = prover(prover_socket, &server_addr, &uri);

    let ((), (sent, received, _session_info)): ((), (Vec<u8>, Vec<u8>, SessionInfo)) =
        smol::future::zip(prover_task, verifier_task).await;

    println!("Successfully verified {}", &uri);
    println!("Verified sent data:\n{}", bytes_to_redacted_string(&sent));
    println!(
        "Verified received data:\n{}",
        bytes_to_redacted_string(&received)
    );
}

async fn prover<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    verifier_socket: T,
    server_addr: &SocketAddr,
    uri: &str,
) {
    let uri = uri.parse::<Uri>().unwrap();
    assert_eq!(uri.scheme().unwrap().as_str(), "https");

    let server_domain = uri.authority().unwrap().host();
    println!("Server domain: {}", server_domain);

    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(
            include_bytes!("../certs/rootCA.der").to_vec(),
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
                    .max_sent_data(1024)
                    .max_recv_data(1024)
                    .build()
                    .unwrap(),
            )
            .crypto_provider(crypto_provider)
            .build()
            .unwrap(),
    )
    .setup(verifier_socket)
    .await
    .unwrap();

    // Connect to TLS Server.
    let tls_client_socket = TcpStream::connect(server_addr).await.unwrap();

    // Pass server connection into the prover.
    let (mpc_tls_connection, prover_fut) = prover.connect(tls_client_socket).await.unwrap();

    // Wrap the connection in a TokioIo compatibility layer to use it with hyper.
    let mpc_tls_connection = FuturesIo::new(mpc_tls_connection);

    // Spawn the Prover to run in the background.
    let prover_task = smol::spawn(prover_fut);

    // MPC-TLS Handshake.
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(mpc_tls_connection)
            .await
            .unwrap();

    // Spawn the connection to run in the background.
    smol::spawn(connection);

    let request = Request::builder()
        .uri(uri.clone())
        .header("Host", server_domain)
        .header("Connection", "close")
        .header("Secret", SECRET)
        .method("GET")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let response = request_sender.send_request(request).await.unwrap();

    assert!(response.status() == StatusCode::OK);

    let prover = prover_task.await.unwrap().start_prove();

    prover.finalize().await.unwrap();
}

async fn verifier<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    socket: T,
) -> (Vec<u8>, Vec<u8>, SessionInfo) {
    let config_validator = ProtocolConfigValidator::builder()
        .max_sent_data(1024)
        .max_recv_data(1024)
        .build()
        .unwrap();

    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(
            include_bytes!("../certs/rootCA.der").to_vec(),
        ))
        .unwrap();
    let crypto_provider = CryptoProvider {
        cert: WebPkiVerifier::new(root_store, None),
        ..Default::default()
    };

    let verifier_config = VerifierConfig::builder()
        .protocol_config_validator(config_validator)
        .crypto_provider(crypto_provider)
        .build()
        .unwrap();
    let verifier = Verifier::new(verifier_config);

    let (mut partial_transcript, session_info) = verifier.verify(socket).await.unwrap();
    partial_transcript.set_unauthed(0);

    let sent = partial_transcript.sent_unsafe().to_vec();
    let sent_data = String::from_utf8(sent.clone()).expect("Verifier expected sent data");
    sent_data
        .find(SERVER_DOMAIN)
        .unwrap_or_else(|| panic!("Verification failed: Expected host {}", SERVER_DOMAIN));

    let received = partial_transcript.received_unsafe().to_vec();
    let response = String::from_utf8(received.clone()).expect("Verifier expected received data");
    response
        .find(SERVER_DOMAIN)
        .unwrap_or_else(|| panic!("Expected valid data from {}", SERVER_DOMAIN));
    assert_eq!(session_info.server_name.as_str(), SERVER_DOMAIN);

    (sent, received, session_info)
}

fn bytes_to_redacted_string(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec())
        .unwrap()
        .replace('\0', "🙈")
}
