use std::fmt;

use bitfield_struct::bitfield;
use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom::number::complete::{be_u8, be_u24};
use nom_derive::*;

use super::{CapabilityCode, Emit};
use crate::{Afi, ParseBe, Safi};

pub fn u32_u8_3(value: u32) -> [u8; 3] {
    // Extract the three least significant bytes as big-endian
    [
        (value >> 16) as u8, // Most significant byte of the remaining 3 bytes
        (value >> 8) as u8,  // Middle byte
        value as u8,         // Least significant byte
    ]
}

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapabilityLlgr {
    pub values: Vec<LLGRValue>,
}

#[bitfield(u8, debug = true)]
#[derive(PartialEq)]
pub struct LLGRFlags {
    #[bits(7)]
    pub resvd: u8,
    #[bits(1)]
    pub f_bit: bool,
}

impl ParseBe<LLGRFlags> for LLGRFlags {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = be_u8(input)?;
        Ok((input, flags.into()))
    }
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct LLGRValue {
    afi: Afi,
    safi: Safi,
    flags: LLGRFlags,
    #[nom(Parse = "be_u24")]
    stale_time: u32,
}

impl Emit for CapabilityLlgr {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::Llgr
    }

    fn len(&self) -> u8 {
        (self.values.len() * 7) as u8
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        for val in self.values.iter() {
            buf.put_u16(val.afi.into());
            buf.put_u8(val.safi.into());
            buf.put_u8(val.flags.into());
            buf.put(&u32_u8_3(val.stale_time)[..]);
        }
    }
}

impl fmt::Display for CapabilityLlgr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = write!(f, "LLGR: ");
        for (i, value) in self.values.iter().enumerate() {
            if i > 0 {
                let _ = write!(f, ", ");
            }
            let _ = write!(
                f,
                "{}/{} flags: {} stale time: {}",
                value.afi,
                value.safi,
                if value.flags.f_bit() { "F" } else { "" },
                value.stale_time
            );
        }
        Ok(())
    }
}
