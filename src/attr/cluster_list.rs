use bytes::{BufMut, BytesMut};
use nom_derive::*;

use super::{encode_tlv, AttributeEncoder, AttributeFlags, AttributeType};
use crate::{AttrEmitter, AttrFlags, AttrType};

#[derive(Clone, NomBE, Debug, Default)]
pub struct ClusterList {
    pub list: Vec<ClusterId>,
}

impl AttributeEncoder for ClusterList {
    fn attr_type() -> AttributeType {
        AttributeType::ClusterList
    }

    fn attr_flag() -> AttributeFlags {
        AttributeFlags::OPTIONAL
    }
}

impl ClusterList {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        let mut attr_buf = BytesMut::new();
        self.list.iter().for_each(|x| x.encode(&mut attr_buf));
        encode_tlv::<Self>(buf, attr_buf);
    }
}

#[derive(Clone, NomBE, Debug)]
pub struct ClusterId {
    pub id: [u8; 4],
}

impl ClusterId {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put(&self.id[..]);
    }
}

impl AttrEmitter for ClusterList {
    fn attr_flags(&self) -> AttrFlags {
        AttrFlags::new().with_optional(true)
    }

    fn attr_type(&self) -> AttrType {
        AttrType::ClusterList
    }

    fn len(&self) -> Option<usize> {
        Some(self.list.len() * 4)
    }

    fn emit(&self, buf: &mut BytesMut) {
        for cluster_id in &self.list {
            buf.put(&cluster_id.id[..]);
        }
    }
}
