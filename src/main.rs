use async_std::net::SocketAddr;

#[macro_use]
extern crate enum_primitive_derive;
extern crate num_traits;

use async_std::io;

mod config;
mod local;
mod protocol;
mod remote;

#[derive(Default, Debug)]
pub struct TlsConfig
{
    password: String,
    remote_addr: String,
    remote_host: String,
    cert: Option<String>,
}

#[async_std::main]
async fn main()
{
    let arg = match std::env::args().nth(1) {
        Some(arg) => arg,
        None => {
            println!("please specify if it is local or remote");
            return;
        },
    };

    if arg == "local" {
        local::start("local.json").await.unwrap();
    } else if arg == "remote" {
        remote::start("remote.json").await.unwrap();
    } else {
        println!("only local or remote is allowed")
    }
}

async fn resolve_addr(addr: &protocol::AddrData, port: u16) -> io::Result<SocketAddr>
{
    match addr {
        protocol::AddrData::DomainName(host) => {
            dns_resolve_retry(5, &(host.clone() + ":" + &port.to_string())).await
        },
        protocol::AddrData::IPv4(i) => Ok(SocketAddr::from((*i, port))),
    }
}

/// # Abstract
/// Sometimes the DNS server just fails to resolve certain hosts randomly
/// which is why we need a retry mechanism
///
/// # Parameters
/// `n` => retry count
/// `host` => host name
///
/// # Return
/// a `SocketAddr` value on success
/// `io::Error` on failure
async fn dns_resolve_retry(n: u32, host: &str) -> io::Result<SocketAddr>
{
    use async_std::net::ToSocketAddrs;
    let mut i = 0;
    loop {
        match host.to_socket_addrs().await {
            Ok(mut s) => {
                break s
                    .next()
                    .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
            },
            Err(e) => {
                if i == n {
                    break Err(e);
                } else {
                    i += 1;
                }
            },
        }
    }
}
