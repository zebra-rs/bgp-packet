use bytes::{BufMut, BytesMut};
use nom_derive::*;
use std::fmt;

use crate::{AttrEmitter, AttrFlags, AttrType};

pub const ORIGIN_IGP: u8 = 0;
pub const ORIGIN_EGP: u8 = 1;
pub const ORIGIN_INCOMPLETE: u8 = 2;

#[derive(Debug, Clone, NomBE)]
pub struct Origin {
    pub origin: u8,
}

impl Origin {
    pub fn new(origin: u8) -> Self {
        Self { origin }
    }

    pub fn short_str(&self) -> &'static str {
        match self.origin {
            ORIGIN_IGP => "i",
            ORIGIN_EGP => "e",
            ORIGIN_INCOMPLETE => "?",
            _ => "?",
        }
    }
}

impl AttrEmitter for Origin {
    fn attr_type(&self) -> AttrType {
        AttrType::Origin
    }

    fn attr_flags(&self) -> AttrFlags {
        AttrFlags::new().with_transitive(true)
    }

    fn len(&self) -> Option<usize> {
        Some(1)
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.origin);
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.origin {
            ORIGIN_IGP => {
                write!(f, "Origin: IGP")
            }
            ORIGIN_EGP => {
                write!(f, "Origin: EGP")
            }
            ORIGIN_INCOMPLETE => {
                write!(f, "Origin: Incomplete")
            }
            _ => {
                write!(f, "Incomplete")
            }
        }
    }
}
