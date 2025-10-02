use std::fmt;

use bytes::{BufMut, BytesMut};
use nom_derive::*;

use crate::{AttrEmitter, AttrFlags, AttrType};

#[derive(Clone, NomBE, Debug, Default)]
pub struct ClusterList {
    pub list: Vec<ClusterId>,
}

impl ClusterList {
    pub fn new() -> Self {
        Self::default()
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

impl fmt::Display for ClusterList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, " Cluster List:")
    }
}
