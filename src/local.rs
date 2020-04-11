use crate::config;
use crate::protocol;
use crate::protocol::Target;
use crate::protocol::CmdType;



use async_native_tls::TlsStream;
use async_std::path::Path;

use crate::TlsConfig;
use async_std::io;
use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use async_std::task;
use futures::AsyncRead;
use futures::AsyncWrite;
use std::io::Cursor;
use std::io::Write;
use std::sync::Arc;

async fn tls_configure(input: &config::LocalConfig) -> io::Result<TlsConfig>
{
	let cert = match input.cert_file.as_ref() {
		Some(ca) => Some(async_std::fs::read_to_string(ca).await?),
		None => None,
	};

	Ok(TlsConfig {
		cert,
		password: input.password.clone(),
		remote_addr: input.remote_addr.clone() + ":" + &input.remote_port.to_string(),
		remote_host: input.remote_host.clone(),
	})
}

pub async fn start<P>(json: P) -> io::Result<()>
where
	P: AsRef<Path>,
{
	let cfg = config::read_local(json).await?;

	let listener = TcpListener::bind(cfg.local_addr.clone() + ":" + &cfg.local_port.to_string())
		.await
		.unwrap();
	let mut iter = listener.incoming();

	let tls_cfg = Arc::new(tls_configure(&cfg).await?);
	

	while let Some(browser) = iter.next().await {
		let browser = browser.unwrap();
		let tls_cfg = tls_cfg.clone();

		task::spawn(async move {
			if let Err(e) = local_session(browser, &tls_cfg).await {
				println!("socks5 handleing error: {}", e);
			}
		});
	}

	Ok(())
}

async fn local_session<T>(mut s: T, cfg: &TlsConfig) -> io::Result<()>
where
	T: 'static + AsyncRead + AsyncWrite + Sized + Send + Unpin,
{
	let (target, cmd)= socks5_negotiate(&mut s).await?;

	match cmd {
		protocol::CmdType::Connect => {
			let tls = remote_auth_establish(cfg, &target.addr, target.port).await?;
			protocol::relay(tls, s).await
		},
		protocol::CmdType::UdpAccociate => todo!()
	}
}

pub async fn socks5_negotiate<T>(s: &mut T) -> io::Result<(Target, CmdType)>
where
	T: AsyncRead + AsyncWrite + Sized + Send + Unpin,
{
	protocol::socks_handshake(s).await?;
	protocol::socks_request(s).await
}


/// # Abstract
/// This function connects to the remote port and establish a TLS connection.
/// The header is sent to the server after as successful TLS handshake.
/// header format:
/// |password-len 1 byte| password content| socks5-ip-port in socks5 format |
///
/// # Parameters
/// `cfg`: TLS config
/// `addr`: ip/host of the `target`
/// `port`: port of the `target`
///
/// # Return Value
/// `io::Result<TlsStream<TcpStream>>` the connection object with headers sent
/// ready for future manipulation
pub async fn remote_auth_establish(
	cfg: &TlsConfig,
	addr: &protocol::AddrData,
	port: u16,
) -> io::Result<TlsStream<TcpStream>>
{
	use byteorder::WriteBytesExt;

	let tcp = TcpStream::connect(&cfg.remote_addr).await?;
	let mut stream =
		match protocol::tls_connect(&cfg.remote_host, cfg.cert.as_ref().map(|s| &s as &str), tcp).await {
			Ok(s) => s,
			Err(e) =>
			{
				println!("error tls -> {}", e);
				return Err(io::Error::from(io::ErrorKind::InvalidData));
			}
		};

	let mut buf = [0u8; 1024];
	let mut cursor = Cursor::new(&mut buf[..]);

	let pass_buf = cfg.password.as_bytes();
	cursor.write_all(pass_buf)?;
	cursor.write_all(b"\r\n")?;
	cursor.write_u8(protocol::CmdType::Connect as u8)?;
	cursor.write_u8(protocol::socks_addr_type(addr) as u8)?;
	protocol::socks_write_address(&mut cursor, addr, port)?;

	let pos = cursor.position() as usize;
	let inner = cursor.into_inner();
	stream.write_all(&inner[..pos]).await?;

	Ok(stream)
}
