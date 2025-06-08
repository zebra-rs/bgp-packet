use bytes::{BufMut, BytesMut};
use nom_derive::*;
use std::net::Ipv4Addr;

use crate::{AttrEmitter, AttrFlags, AttrType};
use super::{AttributeFlags, AttributeType};

#[derive(Clone, NomBE, Debug)]
pub struct OriginatorId {
    pub id: [u8; 4],
}

impl OriginatorId {
    const LEN: u8 = 4;
    const TYPE: AttributeType = AttributeType::OriginatorId;

    pub fn new(id: &Ipv4Addr) -> Self {
        Self { id: id.octets() }
    }

    pub fn id(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.id)
    }

    fn flags() -> AttributeFlags {
        AttributeFlags::OPTIONAL
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(Self::flags().bits());
        buf.put_u8(Self::TYPE.0);
        buf.put_u8(Self::LEN);
        buf.put(&self.id[..]);
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
