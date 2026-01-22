use openssl::ssl::{NameType, SniError, SslAlert, SslRef, SslVerifyMode};
use openssl::x509::X509Name;
use pingora::listeners::tls::TlsSettings;
use pingora::prelude::*;

use crate::config::AppConfig;
use crate::server::certs::CertStoreHandle;

/// Add plain HTTP listener (no TLS)
pub fn add_http_listener(
    svc: &mut pingora_core::services::listening::Service<pingora_proxy::HttpProxy<crate::server::proxy::WafProxy>>,
    cfg: &AppConfig,
) {
    let http_listen = cfg.listen_http_addr();
    svc.add_tcp(&http_listen);
}

/// Add HTTPS listener with mTLS + SNI multi-cert
pub fn add_https_listener(
    svc: &mut pingora_core::services::listening::Service<pingora_proxy::HttpProxy<crate::server::proxy::WafProxy>>,
    cfg: &AppConfig,
    cert_store: CertStoreHandle,
) -> pingora::Result<()> {
    let listen = cfg.listen_addr();
    let certs = &cfg.tls.certs_dir;

    let default_cert = certs.join("server/default/cert.pem");
    let default_key = certs.join("server/default/key.pem");
    let ca_cert = certs.join("ca/ca.crt");

    let mut tls = TlsSettings::intermediate(default_cert.to_str().unwrap(), default_key.to_str().unwrap())?;

    if cfg.mtls_required() {
        tls.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        tls.set_ca_file(ca_cert.to_str().unwrap()).unwrap();
        let ca_list = X509Name::load_client_ca_file(ca_cert.to_str().unwrap()).unwrap();
        tls.set_client_ca_list(ca_list);
    }

    // Pingora 0.6.x: 2-arg callback. Read servername from ssl.servername().
    // Industrial-grade behavior: no disk IO in handshake. Certs are preloaded into memory and hot-reloaded.
    tls.set_servername_callback(move |ssl: &mut SslRef, alert: &mut SslAlert| -> Result<(), SniError> {
        let servername = ssl.servername(NameType::HOST_NAME);
        let Some(name) = servername else {
            return Ok(());
        };

        let Some(pair) = cert_store.lookup(name) else {
            // no matching SNI cert, fall back to default
            return Ok(());
        };

        ssl.set_certificate(&pair.cert).map_err(|_| {
            *alert = SslAlert::ILLEGAL_PARAMETER;
            SniError::ALERT_FATAL
        })?;
        ssl.set_private_key(&pair.key).map_err(|_| {
            *alert = SslAlert::ILLEGAL_PARAMETER;
            SniError::ALERT_FATAL
        })?;

        Ok(())
    });

    tls.enable_h2();
    svc.add_tls_with_settings(&listen, None, tls);
    Ok(())
}
