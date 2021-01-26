extern crate byteorder;
extern crate rust_base58;

use crate::types::Error;
use bech32::u5;
use bech32::ToBase32;
use bech32::WriteBase32;
use byteorder::{LittleEndian, ReadBytesExt};
use rust_base58::ToBase58;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::Cursor;
use std::io::Read;
use std::path::Path;

const FLAG_LEGACY_ADDRESS: u64 = 0x8000000000000000;
const FLAG_P2SH_ADDRESS: u64 = 0x4000000000000000;
const FLAG_BECH32_ADDRESS: u64 = 0x2000000000000000;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Case {
	Upper,
	Lower,
	None,
}

fn get_address(byte_data: Vec<u8>) -> Result<String, String> {
	let byte_data = &byte_data[..25];
	Ok(byte_data.to_base58())
}

fn check_hrp(hrp: &str) -> Result<Case, Error> {
	if hrp.is_empty() || hrp.len() > 83 {
		return Err(Error::InvalidLength);
	}

	let mut has_lower: bool = false;
	let mut has_upper: bool = false;
	for b in hrp.bytes() {
		// Valid subset of ASCII
		if b < 33 || b > 126 {
			return Err(Error::InvalidChar(b as char));
		}

		if b >= b'a' && b <= b'z' {
			has_lower = true;
		} else if b >= b'A' && b <= b'Z' {
			has_upper = true;
		};

		if has_lower && has_upper {
			return Err(Error::MixedCase);
		}
	}
	Ok(match (has_upper, has_lower) {
		(true, false) => Case::Upper,
		(false, true) => Case::Lower,
		(false, false) => Case::None,
		(true, true) => unreachable!(),
	})
}

pub fn encode_to_fmt(
	fmt: &mut dyn fmt::Write,
	hrp: &str,
	data: Vec<u5>,
) -> Result<fmt::Result, Error> {
	let data = &data[..];
	let hrp_lower = match check_hrp(&hrp)? {
		Case::Upper => Cow::Owned(hrp.to_lowercase()),
		Case::Lower | Case::None => Cow::Borrowed(hrp),
	};

	match bech32::Bech32Writer::new(&hrp_lower, fmt) {
		Ok(mut writer) => {
			Ok(writer.write(data.as_ref()).and_then(|_| {
				// Finalize manually to avoid panic on drop if write fails
				writer.finalize()
			}))
		}
		Err(e) => Ok(Err(e)),
	}
}

/// Encode a bech32 payload to string.
///
/// # Errors
/// * If [check_hrp] returns an error for the given HRP.
/// # Deviations from standard
/// * No length limits are enforced for the data part
pub fn encode(hrp: &str, data: Vec<u5>) -> Result<String, Error> {
	let mut buf = String::new();
	encode_to_fmt(&mut buf, hrp, data)?.unwrap();
	Ok(buf)
}

#[derive(Debug)]
pub struct AddressInfo {
	address: String,
	sats: u64,
}

#[derive(Debug)]
pub struct UtxoData {
	map: HashMap<u32, AddressInfo>,
}

pub fn load_binary(binary: &str) -> Result<UtxoData, Error> {
	info!("loading binary at {}", binary);

	if !Path::new(binary).exists() {
		return Err(Error::FileNotFound);
	}

	let mut map: HashMap<u32, AddressInfo> = HashMap::new();

	let mut f = File::open(&binary).expect("no file found");
	let mut buffer = vec![0; 32];

	let mut count = 0;
	loop {
		let res = f.read(&mut buffer);

		if res.is_err() {
			println!("res={:?}", res);
			error!("res={:?}", res);
			break;
		}
		if res.unwrap() == 0 {
			// end of stream
			break;
		}

		let buffer2 = &buffer[24..];
		let mut rdr = Cursor::new(buffer2);
		let mut sats = rdr.read_u64::<LittleEndian>().unwrap();

		let address = if sats & FLAG_LEGACY_ADDRESS != 0 {
			let mut prefixed = [0; 25];
			prefixed[0] = 0x00;
			prefixed[1..].copy_from_slice(&buffer[..24]);
			let ret = get_address(prefixed.to_vec()).unwrap();
			ret
		} else if sats & FLAG_P2SH_ADDRESS != 0 {
			let mut prefixed = [0; 25];
			prefixed[0] = 0x05;
			prefixed[1..].copy_from_slice(&buffer[..24]);
			let ret = get_address(prefixed.to_vec()).unwrap();
			ret
		} else if sats & FLAG_BECH32_ADDRESS != 0 {
			let u5buf = buffer[..20].to_vec().to_base32();
			let mut prefixed: [bech32::u5; 33] = [bech32::u5::try_from_u8(0x00).unwrap(); 33];
			prefixed[1..].copy_from_slice(&u5buf[..32]);
			let encoded = encode("bc", prefixed.to_vec()).unwrap();
			encoded
		} else {
			return Err(Error::UnknownAddressType);
		};

		sats &= !FLAG_LEGACY_ADDRESS;
		sats &= !FLAG_P2SH_ADDRESS;
		sats &= !FLAG_BECH32_ADDRESS;

		map.insert(
			count,
			AddressInfo {
				address: address,
				sats: sats,
			},
		);
		count = count + 1;
	}

	let ret = UtxoData { map: map };

	Ok(ret)
}
