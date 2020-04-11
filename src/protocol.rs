use async_std::io::ReadExt;
use async_std::net::TcpStream;
use async_std::prelude::*;
use byteorder::{NetworkEndian, ReadBytesExt};

use futures::AsyncRead;
use futures::AsyncWrite;

use num_traits::FromPrimitive;
use std::io::Cursor;
use std::io::Write;

use async_std::io;

use async_native_tls::Certificate;
use async_native_tls::TlsConnector;
use async_native_tls::TlsStream;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Primitive)]
#[repr(u8)]
pub enum SocksVersion
{
	V5 = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Primitive)]
pub enum Reserved
{
	ZeroByte = 0,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Primitive)]
pub enum CmdType
{
	Connect = 1,
	UdpAccociate = 3,
}

#[derive(Debug)]
pub struct Target
{
	pub addr: AddrData,
	pub port: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Primitive)]
pub enum AddrType
{
	IPv4 = 1,
	DomainName = 3,
}

pub fn invalid_data() -> io::Error
{
	io::Error::from(io::ErrorKind::InvalidData)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AddrData
{
	IPv4([u8; 4]),
	DomainName(String),
}

/// # Abstract
/// This function relays 2 connections by connecting one's
/// read channel to another's write channel and vice versa
///
/// # Parameters
/// `ch1` channel1
/// `ch2` channel2
///
/// # Return
/// This function returns after the connection is done
pub async fn relay<T, U>(ch1: T, ch2: U) -> io::Result<()>
where
	T: AsyncRead + AsyncWrite + Sized + Send,
	U: AsyncRead + AsyncWrite + Sized + Send,
{
	use futures::AsyncReadExt;
	let (mut r1, mut w1) = ch1.split();
	let (mut r2, mut w2) = ch2.split();

	// let mut f1 = io::copy(&mut r2, &mut w1);
	// let mut f2 = io::copy(&mut r1, &mut w2);
	use futures::FutureExt;

	futures::select! {
		r1 = copy(&mut r2, &mut w1).fuse() => return r1.map(|x|()),
		r2 = copy(&mut r1, &mut w2).fuse() => return r2.map(|x|()),
	}
}

pub async fn copy<R, W>(r: &mut R, w: &mut W) -> io::Result<()>
where
	R: Unpin + AsyncRead + Sized + Send,
	W: Unpin + AsyncWrite + Sized + Send,
{
	loop {
		let mut buf = [0u8; 4096];
		let len = r.read(&mut buf).await?;
		if len == 0 {
			return Ok(());
		}
		let write_buf = &buf[..len];

		w.write_all(write_buf).await?;
	}
}

pub async fn socks_handshake<T>(s: &mut T) -> io::Result<()>
where
	T: AsyncRead + AsyncWrite + Sized + Send + Unpin,
{
	let mut socks5: [u8; 2] = [0u8, 0u8];
	s.read_exact(&mut socks5).await?;
	SocksVersion::from_u8(socks5[0]).ok_or_else(invalid_data)?;
	let n_method = socks5[1];
	let mut arr = [0u8; 255];
	let method_buf = &mut arr[..n_method as usize];
	s.read_exact(method_buf).await?;

	if method_buf.iter().all(|&x| x != 0u8) {
		return Err(invalid_data());
	}

	s.write_all(&[SocksVersion::V5 as u8, Reserved::ZeroByte as u8])
		.await
}

pub async fn socks_request<T>(s: &mut T) -> io::Result<(Target, CmdType)>
where
	T: AsyncRead + AsyncWrite + Sized + Send + Unpin,
{
	let mut socks5 = [0u8; 4];
	s.read_exact(&mut socks5).await?;
	SocksVersion::from_u8(socks5[0]).ok_or_else(invalid_data)?;
	let cmd = CmdType::from_u8(socks5[1]).ok_or_else(invalid_data)?;
	Reserved::from_u8(socks5[2]).ok_or_else(invalid_data)?;
	let addr_type = AddrType::from_u8(socks5[3]).ok_or_else(invalid_data)?;

	let (addr, port) = socks_read_address(addr_type, s).await?;

	s.write_all(&[
		SocksVersion::V5 as u8,
		0x00, // Succeed
		0x00, // Reserved
		0x01, // IPv4 format
		// dummy IP address
		0x00,
		0x00,
		0x00,
		0x00,
		// dummy port
		0x00,
		0x00,
	])
	.await?;

	Ok((Target { addr, port }, cmd))
}

pub fn socks_addr_type(data: &AddrData) -> AddrType
{
	match data {
		AddrData::DomainName { .. } => AddrType::DomainName,
		AddrData::IPv4 { .. } => AddrType::IPv4,
	}
}

pub fn socks_write_address<T>(s: &mut T, addr: &AddrData, port: u16) -> io::Result<()>
where
	T: Unpin + std::io::Write + Sized + Send,
{
	use byteorder::WriteBytesExt;

	match addr {
		AddrData::IPv4(ip) => {
			let mut buf = [ip[0], ip[1], ip[2], ip[3], 0, 0];
			let mut cursor = Cursor::new(&mut buf[4..]);
			cursor.write_u16::<NetworkEndian>(port)?;
			s.write_all(&buf)
		},
		AddrData::DomainName(name) => {
			let bytes = name.as_bytes();
			let mut buf = [0u8; 1 + 255 + 2];

			let mut cursor = Cursor::new(&mut buf[..]);
			cursor.write_u8(bytes.len() as u8).unwrap();
			cursor.write_all(bytes).unwrap();
			cursor.write_u16::<NetworkEndian>(port).unwrap();

			let pos = cursor.position() as usize;
			s.write_all(&(cursor.into_inner()[..pos]))
		},
	}
}

pub async fn socks_read_address<T>(addr_type: AddrType, s: &mut T) -> io::Result<(AddrData, u16)>
where
	T: std::marker::Unpin + AsyncRead + Sized + Send,
{
	match addr_type {
		AddrType::IPv4 => {
			let mut addr_port = [0u8; 6];
			s.read_exact(&mut addr_port).await?;
			let v4addr = [addr_port[0], addr_port[1], addr_port[2], addr_port[3]];

			let port = Cursor::new(&addr_port[4..])
				.read_u16::<NetworkEndian>()
				.unwrap();
			Ok((AddrData::IPv4(v4addr), port))
		},
		AddrType::DomainName => {
			let mut len = 0u8;
			s.read_exact(std::slice::from_mut(&mut len)).await?;
			let mut name = [0u8; 255];
			let name = &mut name[..len as usize];
			s.read_exact(name).await?;
			let domain_name = std::str::from_utf8(name).or_else(|_| Err(invalid_data()))?;

			let mut port_buffer = [0u8; 2];
			s.read_exact(&mut port_buffer).await?;
			let port = Cursor::new(port_buffer)
				.read_u16::<NetworkEndian>()
				.unwrap();

			Ok((AddrData::DomainName(domain_name.to_owned()), port))
		},
	}
}

pub async fn relay_target_tcp<T>(addr: &AddrData, port: u16, channel: T) -> io::Result<()>
where
	T: AsyncRead + AsyncWrite + Sized + Send,
{
	let addr = crate::resolve_addr(addr, port).await?;

	let target = TcpStream::connect(addr).await?;
	relay(target, channel).await
}

#[allow(dead_code)]
#[allow(unused_variables)]
pub async fn relay_target_udp<T>(addr: &AddrData, port: u16, channel: T) {}

pub async fn tls_connect<H, T>(
	remote_host: H,
	cert: Option<&str>,
	base: T,
) -> async_native_tls::Result<TlsStream<T>>
where
	T: Unpin + AsyncRead + AsyncWrite,
	H: AsRef<str>,
{
	let conn = cert.map(|cert| {
		TlsConnector::new().add_root_certificate(Certificate::from_pem(&cert.as_bytes()).unwrap())
	});

	match conn {
		Some(conn) => {
			conn.danger_accept_invalid_hostnames(true)
				.danger_accept_invalid_certs(true)
				.connect(remote_host.as_ref(), base)
				.await
		},
		None => async_native_tls::connect(remote_host.as_ref(), base).await,
	}
}
