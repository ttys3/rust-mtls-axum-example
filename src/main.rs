// axum mTLS example based on https://github.com/tokio-rs/axum/blob/main/examples/low-level-rustls/src/main.rs
use axum::{extract::ConnectInfo, routing::get, Router};
use futures_util::future::poll_fn;
use hyper::server::{
    accept::Accept,
    conn::{AddrIncoming, Http},
};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::{fs::File, io::BufReader, net::SocketAddr, pin::Pin, sync::Arc};
use tokio::net::TcpListener;
use tokio_rustls::{
    rustls,
    rustls::{Certificate, PrivateKey, ServerConfig},
    TlsAcceptor,
};
use tower::MakeService;

use rustls_pemfile::Item;

#[tokio::main]
async fn main() {
    // Set the RUST_LOG, if it hasn't been explicitly defined
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "rust_mtls_axum_example=debug")
    }
    tracing_subscriber::fmt::init();

    let listen_addr = "127.0.0.1:3000";

    let cert = "./tls/server.pem";
    let key = "./tls/server-key-pkcs8.pem";
    let ca = Some("./tls/ca.pem");

    let rustls_config = build_rustls_server_config(cert, key, ca).await;

    let acceptor = TlsAcceptor::from(rustls_config);

    let listener = TcpListener::bind(listen_addr).await.unwrap();
    let mut listener = AddrIncoming::from_listener(listener).unwrap();

    let mut app = Router::new()
        .route("/", get(handler))
        .into_make_service_with_connect_info::<SocketAddr, _>();

    tracing::info!("listening on https://{}", listen_addr);

    loop {
        let stream = poll_fn(|cx| Pin::new(&mut listener).poll_accept(cx))
            .await
            .unwrap()
            .unwrap();

        let acceptor = acceptor.clone();

        let app = app.make_service(&stream).await.unwrap();

        tokio::spawn(async move {
            if let Ok(stream) = acceptor.accept(stream).await {
                let _ = Http::new().serve_connection(stream, app).await;
            }
        });
    }
}

async fn handler(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> String {
    addr.to_string()
}

async fn build_rustls_server_config(cert: &str, key: &str, ca: Option<&str>) -> Arc<ServerConfig> {
    let cert = tokio::fs::read(cert).await.unwrap();
    let key = tokio::fs::read(key).await.unwrap();

    // get pem from file
    let cert = rustls_pemfile::certs(&mut cert.as_ref()).unwrap();
    let key = match rustls_pemfile::read_one(&mut key.as_ref()).unwrap() {
        Some(Item::RSAKey(key)) | Some(Item::PKCS8Key(key)) => key,
        // rustls only support PKCS8, does not support ECC private key
        _ => panic!("private key invalid or not supported"),
    };
    let cert = cert.into_iter().map(rustls::Certificate).collect();
    let key = rustls::PrivateKey(key);

    let config_builder = rustls::ServerConfig::builder().with_safe_defaults();

    let mut server_config = match ca {
        None => config_builder
            .with_no_client_auth()
            .with_single_cert(cert, key)
            .expect("bad certificate/key"),
        Some(ca) => {
            let ca = tokio::fs::read(ca).await.unwrap();
            if let Some(Item::X509Certificate(ca)) =
                rustls_pemfile::read_one(&mut ca.as_ref()).unwrap()
            {
                let mut root_cert_store = rustls::RootCertStore::empty();
                root_cert_store
                    .add(&rustls::Certificate(ca))
                    .expect("bad ca cert");
                config_builder
                    .with_client_cert_verifier(rustls::server::AllowAnyAuthenticatedClient::new(
                        root_cert_store,
                    ))
                    .with_single_cert(cert, key)
                    .expect("bad certificate/key")
            } else {
                panic!("invalid root ca cert")
            }
        }
    };

    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(server_config)
}
