use std::fmt;

use nom_derive::*;

use super::{CapabilityCode, Emit};

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapabilityDynamicCapability {}

impl Emit for CapabilityDynamicCapability {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::DynamicCapability
    }
}

impl fmt::Display for CapabilityDynamicCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Dynamic Capability")
    }
}
