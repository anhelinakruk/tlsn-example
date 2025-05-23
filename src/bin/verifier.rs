use clap::Parser;
use macro_rules_attribute::apply;
use smol::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    spawn,
};
use smol_macros::main;
use tls_core::verify::WebPkiVerifier;
use tlsn_common::config::ProtocolConfigValidator;
use tlsn_core::CryptoProvider;
use tlsn_example::{AppState, args::Args};
use tlsn_verifier::{SessionInfo, Verifier, VerifierConfig};
use tracing::Level;

#[apply(main!)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::fmt()
        .with_max_level(Level::DEBUG)
        .init();

    let args = Args::parse();
    let app_state = AppState::new(&args)?;

    tracing::info!("starting...");
    let listener = TcpListener::bind(app_state.clone().verifier_addr).await?;

    loop {
        let (socket, _) = listener.accept().await.unwrap();
        let app_state = app_state.clone();
        let verifier_task = spawn(async move {
            let (sent, received, session_info) = verifier(socket, &app_state).await;
            tracing::info!("sent: {:?}", sent);
            tracing::info!("received: {:?}", received);
            tracing::info!("session_info: {:?}", session_info);
        });

        verifier_task.await;
    }
}

async fn verifier<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    socket: T,
    app_state: &AppState,
) -> (Vec<u8>, Vec<u8>, SessionInfo) {
    let config_validator = ProtocolConfigValidator::builder()
        .max_sent_data(app_state.max_sent_data)
        .max_recv_data(app_state.max_recv_data)
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
        .find(app_state.server_domain.as_str())
        .unwrap_or_else(|| {
            panic!(
                "Verification failed: Expected host {}",
                app_state.server_domain
            )
        });

    let received = partial_transcript.received_unsafe().to_vec();

    (sent, received, session_info)
}
