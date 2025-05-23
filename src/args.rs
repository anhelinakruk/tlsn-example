use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[arg(long, env = "SERVER_DOMAIN", default_value = "localhost")]
    pub server_domain: String,

    #[arg(long, env = "SERVER_PORT", default_value_t = 3001)]
    pub server_port: u16,

    #[arg(long, env = "SERVER_ADDR", default_value = "127.0.0.1")]
    pub server_addr: String,

    #[arg(long, env = "VERIFIER_ADDR", default_value = "127.0.0.1:8079")]
    pub verifier_addr: String,

    #[arg(long, env = "MAX_SENT_DATA", default_value_t = 1 << 12)]
    pub max_sent_data: usize,

    #[arg(long, env = "MAX_RECV_DATA", default_value_t = 1 << 14)]
    pub max_recv_data: usize,

    #[arg(long, env = "SECRET", default_value = "TLSNotary's private key 🤡")]
    pub secret: String,
}
