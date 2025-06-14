use bytes::{BufMut, BytesMut};
use nom_derive::*;
use std::net::Ipv4Addr;

use crate::{AttrEmitter, AttrFlags, AttrType};

#[derive(Clone, NomBE, Debug)]
pub struct OriginatorId {
    pub id: [u8; 4],
}

impl OriginatorId {
    pub fn new(id: &Ipv4Addr) -> Self {
        Self { id: id.octets() }
    }

    pub fn id(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.id)
    }
}

impl AttrEmitter for OriginatorId {
    fn attr_flags(&self) -> AttrFlags {
        AttrFlags::new().with_optional(true)
    }

    fn attr_type(&self) -> AttrType {
        AttrType::OriginatorId
    }

    fn len(&self) -> Option<usize> {
        Some(4)
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.id[..]);
    }
}
