use std::fmt;

use bytes::{BufMut, BytesMut};
use nom_derive::*;

use super::{CapabilityCode, Emit};
use crate::{Afi, Safi};

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapabilityLlgr {
    pub values: Vec<LLGRValue>,
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct LLGRValue {
    afi: Afi,
    safi: Safi,
    flags_stale_time: u32,
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
            buf.put_u32(val.flags_stale_time);
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
                "{}/{} flags_stale: {}",
                value.afi, value.safi, value.flags_stale_time
            );
        }
        Ok(())
    }
}
