use std::fmt;

use nom_derive::*;

use super::{CapCode, Emit};

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapDynamic {}

impl Emit for CapDynamic {
    fn code(&self) -> CapCode {
        CapCode::DynamicCapability
    }
}

impl fmt::Display for CapDynamic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Dynamic Capability")
    }
}
