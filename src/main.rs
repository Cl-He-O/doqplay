use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore};

use trust_dns_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    Resolver,
};

fn main() {
    let mut name_server_config = NameServerConfig::new(
        SocketAddr::new(Ipv4Addr::new(94, 140, 14, 14).into(), 853),
        Protocol::Quic,
    );
    name_server_config.tls_dns_name = Some("dns.adguard.com".into());

    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|a| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(a.subject, a.spki, a.name_constraints)
    }));

    let client_config = ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let mut adguard_doq = ResolverConfig::new();
    adguard_doq.add_name_server(name_server_config);
    adguard_doq.set_tls_client_config(Arc::new(client_config));

    let resolver = Resolver::new(adguard_doq, ResolverOpts::default()).unwrap();

    print!(
        "{}",
        match resolver.lookup_ip(match std::env::args().nth(1) {
            Some(name) => name,
            None => return,
        }) {
            Ok(lo) => lo,
            Err(err) => {
                println!("{err}");
                return;
            }
        }
        .iter()
        .fold(String::new(), |s, lo| s + &lo.to_string() + "\n")
    );
}
