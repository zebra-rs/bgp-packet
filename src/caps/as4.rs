use std::fmt;

use bytes::{BufMut, BytesMut};
use nom_derive::*;

use super::{CapabilityCode, Emit};

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityAs4 {
    pub asn: u32,
}

impl CapabilityAs4 {
    pub fn new(asn: u32) -> Self {
        Self { asn }
    }
}

impl Emit for CapabilityAs4 {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::As4
    }

    fn len(&self) -> u8 {
        4
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        buf.put_u32(self.asn);
    }
}

impl fmt::Display for CapabilityAs4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "4 Octet AS: {}", self.asn)
    }
}
