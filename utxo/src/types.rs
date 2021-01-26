#[derive(Debug)]
pub enum Error {
	FileNotFound,
	InvalidLength,
	MixedCase,
	InvalidChar(char),
	UnknownAddressType,
}
