use crate::config;
use crate::config::RemoteConfig;
use crate::protocol;
use async_std::path::Path;

use async_native_tls::Identity;
use async_native_tls::TlsAcceptor;
use async_std::io;
use async_std::net::TcpListener;
use async_std::prelude::*;
use async_std::task;
use futures::AsyncRead;
use futures::AsyncWrite;
use std::sync::Arc;

use async_std::net::TcpStream;
use num_traits::FromPrimitive;

pub async fn start<P>(cfg_file: P) -> io::Result<()>
where
    P: AsRef<Path>,
{
    let cfg = config::read_remote(cfg_file).await?;

    remote_run(cfg).await
}

async fn init_tls_remote(pfx: &str, password: &str) -> io::Result<TlsAcceptor>
{
    let id = Identity::from_pkcs12(&async_std::fs::read(pfx).await?, password).unwrap(); //or_else(|_| Err(protocol::invalid_data()))?;

    let tls = native_tls::TlsAcceptor::new(id)
        .or_else(|_| Err(protocol::invalid_data()))?
        .into();

    Ok(tls)
}

async fn remote_run(cfg: RemoteConfig) -> io::Result<()>
{
    let acceptor = Arc::new(init_tls_remote(&cfg.pfx, &cfg.pfx_password).await?);

    let listener =
        TcpListener::bind(cfg.remote_addr.clone() + ":" + &cfg.remote_port.to_string()).await?;

    let mut incoming = listener.incoming();
    let cfg = Arc::new(cfg);

    while let Some(stream) = incoming.next().await {
        let acceptor = acceptor.clone();
        let stream = stream.unwrap();
        let cfg = cfg.clone();

        task::spawn(async move {
            let stream = match acceptor.accept(stream).await {
                Ok(tls_stream) => tls_stream,
                Err(_) => return,
            };

            if let Err(e) = remote_session(stream, &cfg).await {
                println!("session error -> {}", e);
            };
        });
    }

    Ok(())
}

async fn https<T>(local: T, cfg: &RemoteConfig, buf: &[u8]) -> io::Result<()>
where
    T: AsyncRead + AsyncWrite + Sized + Send,
{
    let mut stream =
        TcpStream::connect(cfg.web_addr.clone() + ":" + &cfg.web_port.to_string()).await?;
    stream.write_all(buf).await?;

    protocol::relay(stream, local).await
}

/// # Abstract
/// Establish a session with a socket from local
///
/// # Parameter
/// `local` the connection from local
/// `cfg` config data
///
/// # Return
/// This function does not return until the session is done
async fn remote_session<T>(mut local: T, cfg: &RemoteConfig) -> io::Result<()>
where
    T: AsyncRead + AsyncWrite + Sized + Send + Unpin,
{
    let mut auth_buf = [0_u8; 1024];

    if let Auth::GfwProber(index) = auth(&mut local, cfg.password.as_bytes(), &mut auth_buf).await?
    {
        return https(local, cfg, &auth_buf[..index as usize]).await;
    }

    let mut meta_buf = [0u8; 2];
    local.read(&mut meta_buf).await?;
    let command = protocol::CmdType::from_u8(meta_buf[0]).ok_or_else(protocol::invalid_data)?;

    let addr_type = protocol::AddrType::from_u8(meta_buf[1]).ok_or_else(protocol::invalid_data)?;
    let (addr, port) = protocol::socks_read_address(addr_type, &mut local).await?;

    match command {
        protocol::CmdType::Connect => protocol::relay_target_tcp(&addr, port, local).await,
        protocol::CmdType::UdpAccociate => todo!(),
    }
}

enum Auth
{
    GreaterFire,
    GfwProber(u16),
}

/// # Abstract
/// The authentication process
/// if it is a connection from local, the first few bytes received should be:
/// |password|"\r\n"
/// if not, then relay this session to the fake web
///
/// # Parameter
/// `local`: connection from local
/// `password`: the password set by configuration
/// `auth_buf`: a buffer to keep first received bytes, which will be sent to
/// the fake web if the authentication fails
async fn auth<T>(local: &mut T, password: &[u8], auth_buf: &mut [u8; 1024]) -> io::Result<Auth>
where
    T: AsyncRead + AsyncWrite + Sized + Send + Unpin,
{
    let mut index = 0;

    let pass_len = password.len();
    let pass_buf = &mut auth_buf[..pass_len];
    let len = pass_buf.len();

    while index < len {
        let rest = &mut pass_buf[index..];
        match local.read(rest).await {
            Ok(s) => index += s,
            Err(_) => return Ok(Auth::GfwProber(index as u16)),
        }
        let buf_in = &pass_buf[..index];
        if &password[..buf_in.len()] != buf_in {
            return Ok(Auth::GfwProber(index as u16));
        }
    }

    let mut line_break = &mut auth_buf[index..index + 2];
    local.read_exact(&mut line_break).await?;
    if &line_break != b"\r\n" {
        return Ok(Auth::GfwProber(index as u16));
    }

    Ok(Auth::GreaterFire)
}
