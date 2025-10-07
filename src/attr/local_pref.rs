use std::fmt;

use bytes::{BufMut, BytesMut};
use nom_derive::*;

use crate::{AttrEmitter, AttrFlags, AttrType};

#[derive(Clone, NomBE, Debug)]
pub struct LocalPref {
    pub local_pref: u32,
}

impl LocalPref {
    pub fn new(local_pref: u32) -> Self {
        Self { local_pref }
    }
}

impl AttrEmitter for LocalPref {
    fn attr_flags(&self) -> AttrFlags {
        AttrFlags::new().with_transitive(true)
    }

    fn attr_type(&self) -> AttrType {
        AttrType::LocalPref
    }

    fn len(&self) -> Option<usize> {
        Some(4)
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u32(self.local_pref);
    }
}

impl fmt::Display for LocalPref {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Local Pref: {}", self.local_pref)
    }
}
