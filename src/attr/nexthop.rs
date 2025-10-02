use std::fmt;
use std::net::Ipv4Addr;

use bytes::{BufMut, BytesMut};
use nom_derive::*;

use crate::{AttrEmitter, AttrFlags, AttrType, ParseBe};

#[derive(Clone, NomBE, Debug)]
pub struct NexthopAttr {
    pub next_hop: Ipv4Addr,
}

impl AttrEmitter for NexthopAttr {
    fn attr_flags(&self) -> AttrFlags {
        AttrFlags::new().with_transitive(true)
    }

    fn attr_type(&self) -> AttrType {
        AttrType::NextHop
    }

    fn len(&self) -> Option<usize> {
        Some(4)
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.next_hop.octets()[..]);
    }
}

impl fmt::Display for NexthopAttr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nexthop: {}", self.next_hop)
    }
}
