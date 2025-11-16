use std::fmt;

use bytes::{BufMut, BytesMut};
use nom_derive::*;

use super::{CapabilityCode, Emit};

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapabilitySoftwareVersion {
    pub version: Vec<u8>,
}

impl CapabilitySoftwareVersion {
    pub fn new(version: &str) -> Self {
        Self {
            version: version.into(),
        }
    }
}

impl Emit for CapabilitySoftwareVersion {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::SoftwareVersion
    }

    fn len(&self) -> u8 {
        self.version.len() as u8
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        buf.put(&self.version[..]);
    }
}

impl fmt::Display for CapabilitySoftwareVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Software Version: {}",
            String::from_utf8_lossy(&self.version)
        )
    }
}
