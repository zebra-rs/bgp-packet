use bytes::{BufMut, BytesMut};
use nom_derive::*;
use std::fmt;

use crate::{AttrEmitter, AttrFlags, AttrType};

pub const ORIGIN_IGP: u8 = 0;
pub const ORIGIN_EGP: u8 = 1;
pub const ORIGIN_INCOMPLETE: u8 = 2;

#[derive(Clone, NomBE)]
pub struct Origin {
    pub origin: u8,
}

impl Origin {
    pub fn new(origin: u8) -> Self {
        Self { origin }
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
                write!(f, "i")
            }
            ORIGIN_EGP => {
                write!(f, "e")
            }
            ORIGIN_INCOMPLETE => {
                write!(f, "?")
            }
            _ => {
                write!(f, "?")
            }
        }
    }
}

impl fmt::Debug for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.origin {
            ORIGIN_IGP => {
                write!(f, "IGP")
            }
            ORIGIN_EGP => {
                write!(f, "EGP")
            }
            ORIGIN_INCOMPLETE => {
                write!(f, "Incomplete")
            }
            _ => {
                write!(f, "Incomplete")
            }
        }
    }
}
