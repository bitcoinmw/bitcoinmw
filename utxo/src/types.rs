#[derive(Debug)]
pub enum Error {
	FileNotFound(String),
	InvalidLength,
	MixedCase,
	InvalidChar(char),
	UnknownAddressType,
}
