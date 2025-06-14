use bytes::{BufMut, BytesMut};
use nom_derive::*;

use crate::{AttrEmitter, AttrFlags, AttrType};

#[derive(Clone, Debug, NomBE)]
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
