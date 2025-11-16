use std::fmt;

use bitfield_struct::bitfield;
use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom::number::complete::{be_u8, be_u24};
use nom_derive::*;

use crate::{Afi, CapCode, CapEmit, ParseBe, Safi, u32_u24};

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapLlgr {
    pub values: Vec<LLGRValue>,
}

impl CapLlgr {
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
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
    pub afi: Afi,
    pub safi: Safi,
    flags: LLGRFlags,
    #[nom(Parse = "be_u24")]
    stale_time: u32,
}

impl LLGRValue {
    pub fn new(afi: Afi, safi: Safi, stale_time: u32) -> Self {
        Self {
            afi,
            safi,
            flags: LLGRFlags::default(),
            stale_time,
        }
    }
}

impl CapEmit for CapLlgr {
    fn code(&self) -> CapCode {
        CapCode::LlgrOld
    }

    fn len(&self) -> u8 {
        (self.values.len() * 7) as u8
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        for val in self.values.iter() {
            buf.put_u16(val.afi.into());
            buf.put_u8(val.safi.into());
            buf.put_u8(val.flags.into());
            buf.put(&u32_u24(val.stale_time)[..]);
        }
    }
}

impl fmt::Display for CapLlgr {
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
