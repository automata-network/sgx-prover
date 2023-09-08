use std::prelude::v1::*;

use crypto::keccak_hash;
use eth_types::{SH160, SH256, SU256, U256};

#[derive(Debug, Clone)]
pub struct Encoder<'a> {
    name: &'a str,
    args: Vec<EncoderArgument>,
    reloc: Vec<EncoderReloc>,
    data: Vec<u8>,
    static_flag: bool,
}

pub fn encode_eventsig(eventsig: &str) -> SH256 {
    let mut result = SH256::default();
    result.0 = keccak_hash(eventsig.as_bytes());
    result
}

pub trait EncodeArg<T: ?Sized> {
    fn add(&mut self, val: &T);
}

impl<'a> Encoder<'a> {
    pub fn new(name: &'a str) -> Self {
        Self {
            name: name,
            args: Vec::new(),
            reloc: vec![],
            data: vec![],
            static_flag: false,
        }
    }

    pub fn add_arg(mut self, typ: &str, arg: &[u8]) -> Self {
        assert!(arg.len() <= 32);
        let off = 32 - arg.len();
        let mut buf = [0_u8; 32];
        buf[off..].copy_from_slice(arg);
        self.args.push(EncoderArgument {
            bytes: buf,
            datatype: typ.into(),
        });
        self
    }

    pub fn sig(&self) -> String {
        let arg_list = self
            .args
            .iter()
            .map(|x| x.datatype.clone())
            .filter(|x| x.len() > 0)
            .collect::<Vec<String>>()
            .join(",");
        format!("{}({})", self.name, arg_list)
    }

    pub fn encode(mut self) -> Vec<u8> {
        let arg_size: U256 = (32 * self.args.len()).into();
        for reloc in self.reloc {
            let slice = match reloc.section {
                EncoderRelocSection::Args => &mut self.args[reloc.index].bytes,
                EncoderRelocSection::Data => &mut self.data[reloc.index..reloc.index + 32],
            };
            let offset = U256::from_big_endian(slice);
            let fixed = arg_size + offset;
            fixed.to_big_endian(slice);
        }

        let arg_list = self
            .args
            .iter()
            .map(|x| x.datatype.clone())
            .filter(|x| x.len() > 0)
            .collect::<Vec<String>>()
            .join(",");

        let mut bytes: Vec<u8> = Vec::new();

        if self.name != "" {
            let fn_sig = format!("{}({})", self.name, arg_list);
            bytes.extend_from_slice(&Self::encode_fnsig(&fn_sig));
        }
        for arg in &self.args {
            bytes.extend_from_slice(&arg.bytes);
        }
        bytes.extend(self.data);
        bytes
    }

    pub fn encode_fnsig(fnsig_str: &str) -> [u8; 4] {
        let mut result = [0u8; 4];
        let msg_hash = keccak_hash(fnsig_str.as_bytes());
        result.copy_from_slice(&msg_hash[..4]);
        result
    }

    pub fn encode_bytes(items: &[u8]) -> Vec<u8> {
        let mut data = Vec::<u8>::new();
        let mut args_buf = [0_u8; 32];
        let array_len: U256 = items.len().into();

        // first 32byte value is the array length in big endian
        array_len.to_big_endian(&mut args_buf);
        data.extend_from_slice(&args_buf);

        data.extend_from_slice(items);

        if data.len() % 32 != 0 {
            let padding = 32 - data.len() % 32;
            let mut padding_bytes: Vec<u8> = Vec::new();
            padding_bytes.resize_with(padding, Default::default);
            data.extend_from_slice(&padding_bytes);
        }

        data
    }

    pub fn encode_address_array(items: &Vec<SH160>) -> Vec<u8> {
        let mut data = Vec::<u8>::new();
        let mut args_buf = [0_u8; 32];
        let array_len: U256 = items.len().into();

        // first 32byte value is the array length in big endian
        array_len.to_big_endian(&mut args_buf);
        data.extend_from_slice(&args_buf);

        // zero out the array
        let mut args_buf = [0_u8; 32];

        // all subsequent elements in big endian
        for item in items.iter() {
            args_buf[12..32].copy_from_slice(item.as_bytes());
            data.extend_from_slice(&args_buf);
        }
        data
    }
}

impl<'a> EncodeArg<SH160> for Encoder<'a> {
    fn add(&mut self, arg: &SH160) {
        let mut buf = [0_u8; 32];
        buf[12..32].copy_from_slice(arg.as_bytes());
        self.args.push(EncoderArgument {
            bytes: buf,
            datatype: "address".to_owned(),
        });
    }
}

impl<'a> EncodeArg<bool> for Encoder<'a> {
    fn add(&mut self, arg: &bool) {
        let mut buf = [0_u8; 32];
        buf[31] = arg.clone().into();
        self.args.push(EncoderArgument {
            bytes: buf,
            datatype: "bool".to_owned(),
        });
    }
}

impl<'a> EncodeArg<[u8]> for Encoder<'a> {
    fn add(&mut self, val: &[u8]) {
        self.static_flag = false;
        self.reloc.push(EncoderReloc {
            section: EncoderRelocSection::Args,
            index: self.args.len(),
        });

        let dynarg_data = Self::encode_bytes(val);
        let data_len: U256 = self.data.len().into();
        let mut data_len_buf = [0_u8; 32];
        data_len.to_big_endian(&mut data_len_buf[..]);
        self.args.push(EncoderArgument {
            bytes: data_len_buf,
            datatype: "bytes".to_owned(),
        });
        self.data.extend(dynarg_data);
    }
}

impl<'a> EncodeArg<SH256> for Encoder<'a> {
    fn add(&mut self, arg: &SH256) {
        let mut buf = [0_u8; 32];
        buf.copy_from_slice(arg.as_bytes());
        self.args.push(EncoderArgument {
            bytes: buf,
            datatype: "bytes32".to_owned(),
        });
    }
}

impl<'a> EncodeArg<SU256> for Encoder<'a> {
    fn add(&mut self, val: &SU256) {
        let mut buf = [0_u8; 32];
        val.to_big_endian(&mut buf[..]);
        self.args.push(EncoderArgument {
            bytes: buf,
            datatype: "uint256".to_owned(),
        });
    }
}

impl<'a> EncodeArg<u8> for Encoder<'a> {
    fn add(&mut self, val: &u8) {
        let mut buf = [0_u8; 32];
        buf[31] = val.clone();
        self.args.push(EncoderArgument {
            bytes: buf,
            datatype: "uint8".to_owned(),
        });
    }
}

impl<'a> EncodeArg<Vec<SH160>> for Encoder<'a> {
    fn add(&mut self, val: &Vec<SH160>) {
        self.static_flag = false;
        self.reloc.push(EncoderReloc {
            section: EncoderRelocSection::Args,
            index: self.args.len(),
        });

        let dynarg_data = Self::encode_address_array(val);
        let data_len: U256 = self.data.len().into();
        let mut data_len_buf = [0_u8; 32];
        data_len.to_big_endian(&mut data_len_buf[..]);
        self.args.push(EncoderArgument {
            bytes: data_len_buf,
            datatype: "address[]".to_owned(),
        });
        self.data.extend(dynarg_data);
    }
}

#[derive(Debug, Clone)]
struct EncoderArgument {
    bytes: [u8; 32],
    datatype: String,
}

#[derive(Debug, Clone)]
struct EncoderReloc {
    section: EncoderRelocSection,
    index: usize,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
enum EncoderRelocSection {
    Args,
    Data,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_solidity_encode() {
        glog::init_test();
        let mut enc = Encoder::new("hello");
        let val = SU256::default();
        enc.add(&val);
        let val = 1_u8;
        enc.add(&val);
        glog::info!("{:?}", enc);
    }
}
