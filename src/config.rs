//! Config file definition and config reading



use crate::protocol;
use async_std::fs::read_to_string;
use async_std::io;
use async_std::path::Path;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct LocalConfig
{
	pub local_addr: String,
	pub local_port: u16,

	pub password: String,
	pub remote_addr: String,
	pub remote_host: String,
	pub remote_port: u16,
	pub cert_file: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RemoteConfig
{
	pub password: String,

	pub remote_addr: String,
	pub remote_port: u16,

	pub web_addr: String,
	pub web_port: u16,
	pub pfx: String,
	pub pfx_password: String,
}

pub async fn read_local<P: AsRef<Path>>(path: P) -> io::Result<LocalConfig>
{
	serde_json::from_str(&read_to_string(path).await?).or_else(|_| Err(protocol::invalid_data()))
}

pub async fn read_remote<P: AsRef<Path>>(path: P) -> io::Result<RemoteConfig>
{
	serde_json::from_str(&read_to_string(path).await?).or_else(|_| Err(protocol::invalid_data()))
}
