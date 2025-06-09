use bytes::{BufMut, BytesMut};
use nom::{
    error::{make_error, ErrorKind},
    number::complete::{be_u16, be_u64, be_u8},
};
use nom_derive::*;

use crate::ParseBe;

use super::{AttrEmitter, AttrFlags, AttributeFlags, AttributeType};
use crate::AttrType;

#[derive(Debug, Clone)]
pub struct Aigp {
    aigp: u64,
}

impl ParseBe<Aigp> for Aigp {
    fn parse_be(input: &[u8]) -> nom::IResult<&[u8], Aigp> {
        let (input, typ) = be_u8(input)?;
        if typ != 1 {
            return Err(nom::Err::Error(make_error(input, ErrorKind::Tag)));
        }
        let (input, length) = be_u16(input)?;
        if length != 11 {
            return Err(nom::Err::Error(make_error(input, ErrorKind::Tag)));
        }
        let (_, aigp) = be_u64(input)?;
        Ok((input, Aigp { aigp }))
    }
}

impl Aigp {
    const LEN: u8 = 11; // Type: 1 + Length: 2 + Value: 8 = 11.

    pub fn new(aigp: u64) -> Self {
        Self { aigp }
    }

    fn flags() -> AttributeFlags {
        AttributeFlags::OPTIONAL
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(Self::flags().bits());
        buf.put_u8(AttributeType::Aigp.0);
        buf.put_u8(Self::LEN);
        buf.put_u8(1);
        buf.put_u16(11);
        buf.put_u64(self.aigp);
    }

    pub fn validate_flags(flags: &AttributeFlags) -> bool {
        let mut f = flags.clone();
        f.remove(AttributeFlags::EXTENDED);
        f.bits() == Self::flags().bits()
    }
}

impl AttrEmitter for Aigp {
    fn attr_flags(&self) -> AttrFlags {
        AttrFlags::new().with_optional(true)
    }

    fn attr_type(&self) -> AttrType {
        AttrType::Aigp
    }

    fn len(&self) -> Option<usize> {
        Some(11) // Fixed length: Type(1) + Length(2) + Value(8) = 11
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(1); // Type
        buf.put_u16(11); // Length
        buf.put_u64(self.aigp); // Value
    }
}
