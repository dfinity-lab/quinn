use std::{fs, io, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use futures::StreamExt;
use http::{Request, Response, StatusCode};
use quinn::{CertificateChain, PrivateKey};
use structopt::{self, StructOpt};
use tracing::{error, info};
use tracing_subscriber::filter::LevelFilter;

use quinn_h3::{
    self,
    server::{self, RecvRequest},
    Body,
};

const EXPECTED_RTT_MS: u64 = 170;
// Window size needed to avoid pipeline stalls
const MAX_STREAM_BANDWIDTH_BYTES: u64 = 5 << 20;
const STREAM_RWND: u64 = MAX_STREAM_BANDWIDTH_BYTES / 1000 * EXPECTED_RTT_MS;

const INITIAL_WINDOW: u64 = STREAM_RWND;
const MINIMUM_WINDOW: u64 = STREAM_RWND / 8;
const LOSS_REDUCTION_FACTOR: f32 = 0.75;

#[derive(StructOpt, Debug, Clone)]
#[structopt(name = "h3_server")]
struct Opt {
    /// TLS private key in DER format
    #[structopt(parse(from_os_str), short = "k", long = "key", requires = "cert")]
    key: Option<PathBuf>,
    /// TLS certificate in DER format
    #[structopt(parse(from_os_str), short = "c", long = "cert", requires = "key")]
    cert: Option<PathBuf>,
    /// Address to listen on
    #[structopt(long = "listen", default_value = "[::]:4433")]
    listen: SocketAddr,
    /// Domain for generated self-signed certificate
    #[structopt(long, default_value = "localhost")]
    domain: String,
    /// Receive window
    #[structopt(long)]
    rwnd: Option<u64>,
    /// Initial window
    #[structopt(long)]
    initial_wnd: Option<u64>,
    /// Minimum window
    #[structopt(long)]
    min_wnd: Option<u64>,
    /// Loss reduction factor
    #[structopt(long)]
    loss_reduction_factor: Option<f32>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(LevelFilter::INFO.into()),
            )
            .finish(),
    )?;
    let opt: Opt = Opt::from_args();
    let (cert, key) = build_certs(&opt.key, &opt.cert, &opt.domain).expect("failed to build certs");

    let mut congestion_controller = quinn_proto::congestion::NewRenoConfig::default();
    congestion_controller
        .initial_window(opt.initial_wnd.unwrap_or(INITIAL_WINDOW))
        .minimum_window(opt.min_wnd.unwrap_or(MINIMUM_WINDOW))
        .loss_reduction_factor(opt.loss_reduction_factor.unwrap_or(LOSS_REDUCTION_FACTOR));
    let mut transport_config = quinn::TransportConfig::default();
    transport_config
        .max_idle_timeout(Some(Duration::from_secs(30)))?
        .stream_receive_window(opt.rwnd.unwrap_or(STREAM_RWND))?
        .send_window(4 * opt.rwnd.unwrap_or(STREAM_RWND))
        .keep_alive_interval(Some(Duration::from_secs(20)))
        .congestion_controller_factory(Arc::new(congestion_controller));
    let mut server_config = quinn::ServerConfig::default();
    server_config.transport = Arc::new(transport_config);
    let mut server_config = quinn::ServerConfigBuilder::new(server_config);
    server_config.enable_keylog();

    // Configure a server endpoint
    let mut server = server::Builder::with_quic_config(server_config);
    server
        .listen(opt.listen)
        .certificate(cert, key)
        .expect("failed to add cert");

    // Build it, get a stream of incoming connections
    let mut incoming = server.build().expect("bind failed");

    info!("server listening on {}", opt.listen);

    // Handle each connection concurrently, spawning a new task for each of one them
    while let Some(connecting) = incoming.next().await {
        tokio::spawn(async move {
            // Wait for the handshake to complete, get a stream of incoming requests
            let mut incoming_request = match connecting.await {
                Ok(incoming_request) => incoming_request,
                Err(e) => {
                    error!("handshake failed: {:?}", e);
                    return;
                }
            };

            // Handle each request concurently
            while let Some(request) = incoming_request.next().await {
                tokio::spawn(async move {
                    if let Err(e) = handle_request(request).await {
                        error!("request failed: {:?}", e);
                    };
                });
            }
        });
    }

    Ok(())
}

async fn handle_request(recv_request: RecvRequest) -> Result<()> {
    // Receive the request's headers
    let (request, mut sender): (Request<_>, _) = recv_request.await?;
    info!("received request: {:?}", request);
    let path = &request.uri().path()[1..];
    let contents = std::fs::read(path);
    let content_len = contents.as_ref().map_or(0, |contents| contents.len());

    let response = match contents {
        Ok(contents) => Response::builder()
            .status(StatusCode::OK)
            .header("response", "header")
            .body(Body::from(Bytes::from(contents)))?,

        Err(e) => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("response", "header")
            .body(Body::from(e.to_string().as_str()))?,
    };

    sender.send_response(response).await?;
    info!("sent response, length: {}", content_len);

    Ok(())
}

pub fn build_certs(
    key: &Option<PathBuf>,
    cert: &Option<PathBuf>,
    domain: &str,
) -> Result<(CertificateChain, PrivateKey)> {
    if let (Some(ref key_path), Some(ref cert_path)) = (key, cert) {
        let key = fs::read(key_path).context("failed to read private key")?;
        info!("key.der = {:?}", key);
        let key = quinn::PrivateKey::from_der(&key)?;
        let cert_chain = fs::read(cert_path).context("failed to read certificate chain")?;
        info!("cert.der = {:?}", cert_chain);
        let cert = quinn::Certificate::from_der(&cert_chain)?;
        let cert_chain = quinn::CertificateChain::from_certs(vec![cert]);
        Ok((cert_chain, key))
    } else {
        let dirs = directories_next::ProjectDirs::from("org", "quinn", "quinn-examples").unwrap();
        let path = dirs.data_local_dir();
        let cert_path = path.join("cert.der");
        let key_path = path.join("key.der");
        let (cert, key) = match fs::read(&cert_path).and_then(|x| Ok((x, fs::read(&key_path)?))) {
            Ok(x) => x,
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
                info!("generating self-signed certificate");
                let cert = rcgen::generate_simple_self_signed(vec![domain.into()]).unwrap();
                let key = cert.serialize_private_key_der();
                let cert = cert.serialize_der().unwrap();
                fs::create_dir_all(&path).context("failed to create certificate directory")?;
                fs::write(&cert_path, &cert).context("failed to write certificate")?;
                fs::write(&key_path, &key).context("failed to write private key")?;
                (cert, key)
            }
            Err(e) => {
                bail!("failed to read certificate: {}", e);
            }
        };
        let key = quinn::PrivateKey::from_der(&key)?;
        let cert = quinn::Certificate::from_der(&cert)?;
        Ok((quinn::CertificateChain::from_certs(vec![cert]), key))
    }
}
