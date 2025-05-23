use tls_core::verify::WebPkiVerifier;
use tlsn_common::config::ProtocolConfigValidator;
use tlsn_core::CryptoProvider;
use tlsn_verifier::{SessionInfo, Verifier, VerifierConfig};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    spawn,
};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::Level;

const SERVER_DOMAIN: &str = "localhost";
const MAX_SENT_DATA: usize = 1 << 12;
const MAX_RECV_DATA: usize = 1 << 14;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::fmt()
        .with_max_level(Level::DEBUG)
        .init();

    tracing::info!("starting...");
    let listener = TcpListener::bind("127.0.0.1:8079").await.unwrap();

    loop {
        let (socket, _) = listener.accept().await.unwrap();
        let verifier_task = spawn(async move {
            let (sent, received, session_info) = verifier(socket).await;
            tracing::info!("sent: {:?}", sent);
            tracing::info!("received: {:?}", received);
            tracing::info!("session_info: {:?}", session_info);
        });

        let ok = verifier_task.await;
        if let Err(e) = ok {
            tracing::error!("Verifier task failed: {:?}", e);
        }
        tracing::info!("Verifier task completed");
    }
}

async fn verifier<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    socket: T,
) -> (Vec<u8>, Vec<u8>, SessionInfo) {
    let config_validator = ProtocolConfigValidator::builder()
        .max_sent_data(MAX_SENT_DATA)
        .max_recv_data(MAX_RECV_DATA)
        .build()
        .unwrap();

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

    let verifier_config = VerifierConfig::builder()
        .protocol_config_validator(config_validator)
        .crypto_provider(crypto_provider)
        .build()
        .unwrap();
    let verifier = Verifier::new(verifier_config);

    let (mut partial_transcript, session_info) = verifier.verify(socket.compat()).await.unwrap();
    partial_transcript.set_unauthed(0);

    let sent = partial_transcript.sent_unsafe().to_vec();
    let sent_data = String::from_utf8(sent.clone()).expect("Verifier expected sent data");
    sent_data
        .find(SERVER_DOMAIN)
        .unwrap_or_else(|| panic!("Verification failed: Expected host {}", SERVER_DOMAIN));

    let received = partial_transcript.received_unsafe().to_vec();

    (sent, received, session_info)
}
