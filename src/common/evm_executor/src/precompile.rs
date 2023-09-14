use std::prelude::v1::*;

use std::collections::BTreeMap;

use crypto::{keccak_hash, secp256k1_ecdsa_recover, sha256_sum};
use eth_types::{HexBytes, H160, U256};

use evm::{
    executor::stack::{
        IsPrecompileResult, PrecompileFailure, PrecompileHandle, PrecompileOutput,
        PrecompileSet as EvmPrecompileSet,
    },
    ExitFatal, ExitSucceed,
};
use num_bigint::BigUint;

pub type PrecompileResult = Result<PrecompileOutput, PrecompileFailure>;

#[derive(Debug, Default)]
pub struct PrecompileSet {
    fns: BTreeMap<H160, Box<dyn PrecompiledContract + Send + Sync>>,
}

impl PrecompileSet {
    pub fn berlin() -> Self {
        let mut def = Self::default();
        for i in 1..=9 {
            def.add(i, PrecompileUnimplemented { addr: i });
        }

        def.add(1, PrecompileEcrecover {});
        def.add(2, PrecompileSha256Hash {});
        def.add(3, PrecompileRipemd160Hash {});
        def.add(4, PrecompileDataCopy {});
        def.add(
            5,
            PrecompileBigModExp {
                eip2565: true,
                length_limit: None,
            },
        );
        def.add(6, PrecompileAddIstanbul {});
        def.add(7, PrecompileMulIstanbul {});
        def.add(8, PrecompilePairIstanbul {});
        // def.add(9, PrecompileBlake2F {});
        // 9: 0x6ad71132f7493ae1c13b4e2c2742ba9ad7432971815f48c188aa54bee9a7e9ce blake2F

        def
    }

    pub fn scroll() -> Self {
        let mut def = Self::default();
        for i in 1..=9 {
            def.add(i, PrecompileUnimplemented { addr: i });
        }

        def.add(1, PrecompileEcrecover {});
        // def.add(2, PrecompileSha256Hash {});
        // def.add(3, PrecompileRipemd160Hash {});
        def.add(4, PrecompileDataCopy {});
        def.add(
            5,
            PrecompileBigModExp {
                eip2565: true,
                length_limit: Some(32),
            },
        );
        def.add(6, PrecompileAddIstanbul {});
        def.add(7, PrecompileMulIstanbul {});
        def.add(8, PrecompilePairIstanbul {});

        def
    }

    pub fn get_addresses(&self) -> Vec<H160> {
        self.fns.keys().map(|k| k.clone()).collect()
    }

    fn add<P>(&mut self, idx: u8, p: P)
    where
        P: PrecompiledContract + Send + Sync + 'static,
    {
        let mut addr = H160::default();

        addr.0[addr.0.len() - 1] = idx;
        self.fns.insert(addr.clone(), Box::new(p));
    }
}

impl EvmPrecompileSet for PrecompileSet {
    fn execute(&self, handle: &mut impl PrecompileHandle) -> Option<PrecompileResult> {
        let p = self.fns.get(&handle.code_address())?;
        Some(run_precompiled_contract(p.as_ref(), handle))
    }

    fn is_precompile(&self, address: H160, _remaining_gas: u64) -> IsPrecompileResult {
        IsPrecompileResult::Answer {
            is_precompile: self.fns.contains_key(&address),
            extra_cost: 0,
        }
    }
}

fn run_precompiled_contract<P>(p: &P, handle: &mut impl PrecompileHandle) -> PrecompileResult
where
    P: PrecompiledContract + ?Sized,
{
    let gas_cost = p.required_gas(handle.input());
    handle.record_cost(gas_cost)?;
    p.run(handle.input())
}

pub trait PrecompiledContract: core::fmt::Debug {
    fn calculate_gas(&self, input: &[u8], per_word_gas: usize, base_gas: usize) -> u64 {
        ((input.len() + 31) / 32 * per_word_gas + base_gas) as u64
    }
    fn required_gas(&self, input: &[u8]) -> u64;
    fn run(&self, input: &[u8]) -> PrecompileResult;
}

#[derive(Debug)]
pub struct PrecompileUnimplemented {
    addr: u8,
}

impl PrecompiledContract for PrecompileUnimplemented {
    fn required_gas(&self, _: &[u8]) -> u64 {
        0
    }
    fn run(&self, _: &[u8]) -> PrecompileResult {
        glog::error!("unimplemented addr: {}", self.addr);
        PrecompileResult::Err(PrecompileFailure::Fatal {
            exit_status: ExitFatal::NotSupported,
        })
    }
}

/// Input length for the add operation.
const ADD_INPUT_LEN: usize = 128;

/// Input length for the multiplication operation.
const MUL_INPUT_LEN: usize = 128;

/// Pair element length.
const PAIR_ELEMENT_LEN: usize = 192;

/// Reads the `x` and `y` points from an input at a given position.
fn read_point(input: &[u8], pos: usize) -> bn::G1 {
    use bn::{AffineG1, Fq, Group, G1};

    let mut px_buf = [0u8; 32];
    px_buf.copy_from_slice(&input[pos..(pos + 32)]);
    let px = Fq::from_slice(&px_buf).unwrap(); // .unwrap(); //.map_err(|_| Error::Bn128FieldPointNotAMember)?;

    let mut py_buf = [0u8; 32];
    py_buf.copy_from_slice(&input[(pos + 32)..(pos + 64)]);
    let py = Fq::from_slice(&py_buf).unwrap(); //.unwrap(); //.map_err(|_| Error::Bn128FieldPointNotAMember)?;

    if px == Fq::zero() && py == bn::Fq::zero() {
        G1::zero()
    } else {
        AffineG1::new(px, py).map(Into::into).unwrap() //.map_err(|_| Error::Bn128AffineGFailedToCreate)
    }
}

#[derive(Debug)]
pub struct PrecompileAddIstanbul {}

impl PrecompiledContract for PrecompileAddIstanbul {
    fn required_gas(&self, _: &[u8]) -> u64 {
        150
    }
    fn run(&self, input: &[u8]) -> PrecompileResult {
        use bn::AffineG1;

        let mut input = input.to_vec();
        input.resize(ADD_INPUT_LEN, 0);

        let p1 = read_point(&input, 0);
        let p2 = read_point(&input, 64);

        let mut output = [0u8; 64];
        if let Some(sum) = AffineG1::from_jacobian(p1 + p2) {
            sum.x()
                .into_u256()
                .to_big_endian(&mut output[..32])
                .unwrap();
            sum.y()
                .into_u256()
                .to_big_endian(&mut output[32..])
                .unwrap();
        }

        Ok(PrecompileOutput {
            exit_status: ExitSucceed::Returned,
            output: output.into(),
        })
    }
}

#[derive(Debug)]
pub struct PrecompileMulIstanbul {}

impl PrecompiledContract for PrecompileMulIstanbul {
    fn required_gas(&self, _: &[u8]) -> u64 {
        6000
    }
    fn run(&self, input: &[u8]) -> PrecompileResult {
        use bn::AffineG1;

        let mut input = input.to_vec();
        input.resize(MUL_INPUT_LEN, 0);

        let p = read_point(&input, 0);

        let mut fr_buf = [0u8; 32];
        fr_buf.copy_from_slice(&input[64..96]);
        // Fr::from_slice can only fail on incorect length, and this is not a case.
        let fr = bn::Fr::from_slice(&fr_buf[..]).unwrap();

        let mut out = [0u8; 64];
        if let Some(mul) = AffineG1::from_jacobian(p * fr) {
            mul.x().to_big_endian(&mut out[..32]).unwrap();
            mul.y().to_big_endian(&mut out[32..]).unwrap();
        }

        Ok(PrecompileOutput {
            exit_status: ExitSucceed::Returned,
            output: out.to_vec(),
        })
    }
}

#[derive(Debug)]
pub struct PrecompilePairIstanbul {}

impl PrecompiledContract for PrecompilePairIstanbul {
    fn required_gas(&self, input: &[u8]) -> u64 {
        45000 + (input.len() / 192) as u64 * 34000
    }
    fn run(&self, input: &[u8]) -> PrecompileResult {
        use bn::{AffineG1, AffineG2, Fq, Fq2, Group, Gt, G1, G2};

        if input.len() > 4 * PAIR_ELEMENT_LEN {
            return Err(PrecompileFailure::Fatal {
                exit_status: ExitFatal::Other("errBadPairingInput".into()),
            });
        }

        if input.len() % PAIR_ELEMENT_LEN != 0 {
            return Err(PrecompileFailure::Fatal {
                exit_status: ExitFatal::Other("errBadPairingInput".into()),
            });
        }

        let output = if input.is_empty() {
            U256::from(1u64)
        } else {
            let elements = input.len() / PAIR_ELEMENT_LEN;
            let mut vals = Vec::with_capacity(elements);

            const PEL: usize = PAIR_ELEMENT_LEN;

            for idx in 0..elements {
                let mut buf = [0u8; 32];

                buf.copy_from_slice(&input[(idx * PEL)..(idx * PEL + 32)]);
                let ax = Fq::from_slice(&buf).unwrap(); //.map_err(|_| Error::Bn128FieldPointNotAMember)?;
                buf.copy_from_slice(&input[(idx * PEL + 32)..(idx * PEL + 64)]);
                let ay = Fq::from_slice(&buf).unwrap(); //.map_err(|_| Error::Bn128FieldPointNotAMember)?;
                buf.copy_from_slice(&input[(idx * PEL + 64)..(idx * PEL + 96)]);
                let bay = Fq::from_slice(&buf).unwrap(); //.map_err(|_| Error::Bn128FieldPointNotAMember)?;
                buf.copy_from_slice(&input[(idx * PEL + 96)..(idx * PEL + 128)]);
                let bax = Fq::from_slice(&buf).unwrap(); //.map_err(|_| Error::Bn128FieldPointNotAMember)?;
                buf.copy_from_slice(&input[(idx * PEL + 128)..(idx * PEL + 160)]);
                let bby = Fq::from_slice(&buf).unwrap(); //.map_err(|_| Error::Bn128FieldPointNotAMember)?;
                buf.copy_from_slice(&input[(idx * PEL + 160)..(idx * PEL + 192)]);
                let bbx = Fq::from_slice(&buf).unwrap(); //.map_err(|_| Error::Bn128FieldPointNotAMember)?;

                let a = {
                    if ax.is_zero() && ay.is_zero() {
                        G1::zero()
                    } else {
                        G1::from(
                            AffineG1::new(ax, ay).unwrap(), //.map_err(|_| Error::Bn128AffineGFailedToCreate)?,
                        )
                    }
                };
                let b = {
                    let ba = Fq2::new(bax, bay);
                    let bb = Fq2::new(bbx, bby);

                    if ba.is_zero() && bb.is_zero() {
                        G2::zero()
                    } else {
                        G2::from(
                            AffineG2::new(ba, bb).unwrap(), //.map_err(|_| Error::Bn128AffineGFailedToCreate)?,
                        )
                    }
                };
                vals.push((a, b))
            }

            let mul = vals
                .into_iter()
                .fold(Gt::one(), |s, (a, b)| s * bn::pairing(a, b));

            if mul == Gt::one() {
                U256::from(1u64)
            } else {
                U256::zero()
            }
        };

        let mut b = [0_u8; 32];
        output.to_big_endian(&mut b);
        Ok(PrecompileOutput {
            exit_status: ExitSucceed::Returned,
            output: b.into(),
        })
    }
}

#[derive(Debug)]
pub struct PrecompileEcrecover {}

impl PrecompiledContract for PrecompileEcrecover {
    fn required_gas(&self, _: &[u8]) -> u64 {
        3000
    }
    fn run(&self, input: &[u8]) -> PrecompileResult {
        fn ecrecover(i: &[u8]) -> Vec<u8> {
            let mut input = [0u8; 128];
            input[..i.len().min(128)].copy_from_slice(&i[..i.len().min(128)]);

            let mut msg = [0u8; 32];
            let mut sig = [0u8; 65];

            msg[0..32].copy_from_slice(&input[0..32]);
            sig[0..32].copy_from_slice(&input[64..96]);
            sig[32..64].copy_from_slice(&input[96..128]);
            sig[64] = input[63];

            let pubkey = match secp256k1_ecdsa_recover(&sig, &msg) {
                Some(pubkey) => pubkey,
                None => return Vec::new(),
            };
            let mut address = keccak_hash(&pubkey);
            address[0..12].copy_from_slice(&[0u8; 12]);
            address.to_vec()
        }

        Ok(PrecompileOutput {
            exit_status: ExitSucceed::Returned,
            output: ecrecover(input),
        })
    }
}

#[derive(Debug)]
pub struct PrecompileSha256Hash {}

impl PrecompiledContract for PrecompileSha256Hash {
    fn required_gas(&self, input: &[u8]) -> u64 {
        self.calculate_gas(input, 12, 60)
    }

    fn run(&self, input: &[u8]) -> PrecompileResult {
        let val = sha256_sum(input);
        Ok(PrecompileOutput {
            exit_status: ExitSucceed::Returned,
            output: val.to_vec(),
        })
    }
}

#[derive(Debug)]
pub struct PrecompileDataCopy {}

impl PrecompiledContract for PrecompileDataCopy {
    // testcase: https://goerli.etherscan.io/tx/0x5e928106ec0115b89df07315d7b980c8a072a00c977c2834ac8b41bfb3241324#internal
    fn required_gas(&self, input: &[u8]) -> u64 {
        self.calculate_gas(input, 3, 15)
    }

    fn run(&self, input: &[u8]) -> PrecompileResult {
        Ok(PrecompileOutput {
            exit_status: ExitSucceed::Returned,
            output: input.to_vec(),
        })
    }
}

#[derive(Debug)]
pub struct PrecompileRipemd160Hash {}

impl PrecompiledContract for PrecompileRipemd160Hash {
    fn required_gas(&self, input: &[u8]) -> u64 {
        self.calculate_gas(input, 120, 600)
    }

    fn run(&self, input: &[u8]) -> PrecompileResult {
        glog::info!("input: {:?}", HexBytes::from(input.to_vec()));
        use ripemd160::{Digest, Ripemd160};
        let output = Ripemd160::digest(input).to_vec();
        let mut val = [0_u8; 32];
        val[12..].copy_from_slice(&output[..]);
        Ok(PrecompileOutput {
            exit_status: ExitSucceed::Returned,
            output: val.into(),
        })
    }
}

// #[derive(Debug)]
// pub struct PrecompileBlake2F {}

// impl PrecompiledContract for PrecompileBlake2F {
//     fn required_gas(&self, mut input: &[u8]) -> u64 {
//         if input.len() != 213 {
//             return 0;
//         }
//         let mut val = [0_u8; 4];
//         val.copy_from_slice(&input[..4]);
//         return u32::from_be_bytes(val) as u64;
//     }

//     fn run(&self, input: &[u8]) -> PrecompileResult {
//         if input.len() != INPUT_LENGTH {
//             return Err(PrecompileFailure::Revert {
//                 exit_status: ExitRevert::Reverted,
//                 output: "Invalid Length".into(),
//             });
//         }

//         let f = match input[212] {
//             1 => true,
//             0 => false,
//             _ => {
//                 return Err(PrecompileFailure::Revert {
//                     exit_status: ExitRevert::Reverted,
//                     output: "Invalid Length".into(),
//                 })
//             }
//         };

//         // rounds 4 bytes
//         let rounds = u32::from_be_bytes(input[..4].try_into().unwrap()) as usize;

//         let mut h = [0u64; 8];
//         let mut m = [0u64; 16];

//         for (i, pos) in (4..68).step_by(8).enumerate() {
//             h[i] = u64::from_le_bytes(input[pos..pos + 8].try_into().unwrap());
//         }
//         for (i, pos) in (68..196).step_by(8).enumerate() {
//             m[i] = u64::from_le_bytes(input[pos..pos + 8].try_into().unwrap());
//         }
//         let t = [
//             u64::from_le_bytes(input[196..196 + 8].try_into().unwrap()),
//             u64::from_le_bytes(input[204..204 + 8].try_into().unwrap()),
//         ];

//         algo::compress(rounds, &mut h, m, t, f);

//         let mut out = [0u8; 64];
//         for (i, h) in (0..64).step_by(8).zip(h.iter()) {
//             out[i..i + 8].copy_from_slice(&h.to_le_bytes());
//         }

//         Ok((gas_used, out.to_vec()))
//     }
// }

#[derive(Debug)]
pub struct PrecompileBigModExp {
    // testcase 0x6baf80b76832ff53cd551d3d607c04596ec45dd098dc7c0ac292f6a1264c1337
    eip2565: bool,
    length_limit: Option<usize>,
}

impl PrecompiledContract for PrecompileBigModExp {
    fn required_gas(&self, input: &[u8]) -> u64 {
        // Padding data to be at least 32 * 3 bytes.
        let mut data: Vec<u8> = input.into();
        while data.len() < 32 * 3 {
            data.push(0);
        }

        let base_len = U256::from(&data[0..32]).as_usize();
        let exp_len = U256::from(&data[32..64]).as_usize();
        let mod_len = U256::from(&data[64..96]).as_usize();

        let input = input.get(96..).unwrap_or(&[]);

        let exp_head = if input.len() <= base_len {
            U256::from(0u64)
        } else {
            if exp_len > 32 {
                U256::from(&input[base_len..base_len + 32])
            } else {
                U256::from(&input[base_len..base_len + exp_len])
            }
        };

        let msb = match exp_head.bits() {
            0 => 0,
            other => other - 1,
        };
        // adjExpLen := new(big.Int)
        let mut adj_exp_len = 0;
        if exp_len > 32 {
            adj_exp_len = exp_len - 32;
            adj_exp_len *= 8;
        }
        adj_exp_len += msb;
        // Calculate the gas cost of the operation
        let mut gas = U256::from(mod_len.max(base_len));

        if self.eip2565 {
            // EIP-2565 has three changes
            // 1. Different multComplexity (inlined here)
            // in EIP-2565 (https://eips.ethereum.org/EIPS/eip-2565):
            //
            // def mult_complexity(x):
            //    ceiling(x/8)^2
            //
            //where is x is max(length_of_MODULUS, length_of_BASE)
            gas += U256::from(7u64);
            gas /= U256::from(8u64);
            gas *= gas;

            gas *= U256::from(adj_exp_len.max(1));

            // 2. Different divisor (`GQUADDIVISOR`) (3)
            gas /= U256::from(3u64);
            if gas.bits() > 64 {
                return u64::MAX;
            }

            // 3. Minimum price of 200 gas
            if gas < U256::from(200u64) {
                return 200;
            }
            return gas.as_u64();
        }
        unimplemented!()
    }

    fn run(&self, input: &[u8]) -> PrecompileResult {
        // Padding data to be at least 32 * 3 bytes.
        let mut data: Vec<u8> = input.into();
        while data.len() < 32 * 3 {
            data.push(0);
        }

        let base_length = U256::from(&data[0..32]);
        let exponent_length = U256::from(&data[32..64]);
        let modulus_length = U256::from(&data[64..96]);

        if base_length > U256::from(usize::max_value())
            || exponent_length > U256::from(usize::max_value())
            || modulus_length > U256::from(usize::max_value())
        {
            panic!(
                "MemoryIndexNotSupported, {}, {}, {}",
                base_length, exponent_length, modulus_length
            )
        }

        let base_length: usize = base_length.as_usize();
        let exponent_length: usize = exponent_length.as_usize();
        let modulus_length: usize = modulus_length.as_usize();

        if let Some(length_limit) = self.length_limit {
            if base_length > length_limit
                || exponent_length > length_limit
                || modulus_length > length_limit
            {
                return Err(PrecompileFailure::Fatal {
                    exit_status: ExitFatal::Other("ModexpUnsupportedInput".into()),
                });
            }
        }

        let mut base_arr = Vec::new();
        let mut exponent_arr = Vec::new();
        let mut modulus_arr = Vec::new();

        for i in 0..base_length {
            if 96 + i >= data.len() {
                base_arr.push(0u8);
            } else {
                base_arr.push(data[96 + i]);
            }
        }
        for i in 0..exponent_length {
            if 96 + base_length + i >= data.len() {
                exponent_arr.push(0u8);
            } else {
                exponent_arr.push(data[96 + base_length + i]);
            }
        }
        for i in 0..modulus_length {
            if 96 + base_length + exponent_length + i >= data.len() {
                modulus_arr.push(0u8);
            } else {
                modulus_arr.push(data[96 + base_length + exponent_length + i]);
            }
        }

        let base = BigUint::from_bytes_be(&base_arr);
        let exponent = BigUint::from_bytes_be(&exponent_arr);
        let modulus = BigUint::from_bytes_be(&modulus_arr);

        let mut result = base.modpow(&exponent, &modulus).to_bytes_be();
        assert!(result.len() <= modulus_length);
        while result.len() < modulus_length {
            result.insert(0, 0u8);
        }

        Ok(PrecompileOutput {
            exit_status: ExitSucceed::Returned,
            output: result,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_ecrecover() {
        glog::init_test();
        let input = HexBytes::from_hex(b"0x9161131deff2aea942dd43fbce9eb5b409b21670953e583fa10499dc52db57e3000000000000000000000000000000000000000000000000000000000000001bae2054dc5b25097032a64cdda29eb1da01a75ac4297249623bed59a44e91ae4b418e411747af2cd5e7e4a2ba2ed86b1d67ab8dccba4fc2adeab18ad66d8551d7").unwrap();
        let run = PrecompileEcrecover {}.run(&input).unwrap();
        let result: HexBytes = run.output.into();
        let expect = HexBytes::from_hex(
            b"0x000000000000000000000000a040a4e812306d66746508bcfbe84b3e73de67fa",
        )
        .unwrap();
        assert_eq!(expect, result);
    }

    #[test]
    fn test_ripemd() {
        glog::init_test();
        let input  = HexBytes::from_hex(b"0x099538be21d9ee24d052fb9bdc46307416b983d076f3bf04ccbe120ed514ca7589c83b3859bb92919a9d1006fbe59aeac6154321ab0ba37d3490a8c90000").unwrap();
        let result: HexBytes = PrecompileRipemd160Hash {}
            .run(&input)
            .unwrap()
            .output
            .into();
        let expect = HexBytes::from_hex(
            b"0x0000000000000000000000006b0f28fb610ce4d01c1d210a6aeb3967bf7bf0f7",
        )
        .unwrap();
        assert_eq!(expect, result);
    }

    #[test]
    fn test_bigexpmod() {
        glog::init_test();
        let input = HexBytes::from_hex(b"0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002005ec467b88826aba4537602d514425f3b0bdf467bbf302458337c45f6021e539000000000000000000000000000000000000000000000000000000000000000f0800000000000011000000000000000000000000000000000000000000000001").unwrap();
        let expect = HexBytes::from_hex(
            b"0x05c3ed0c6f6ac6dd647c9ba3e4721c1eb14011ea3d174c52d7981c5b8145aa75",
        )
        .unwrap();
        let contract = PrecompileBigModExp { eip2565: true };
        let output: HexBytes = contract.run(&input).unwrap().output.into();
        assert_eq!(expect, output);
        assert_eq!(contract.required_gas(&input), 200); // 16
    }
}
