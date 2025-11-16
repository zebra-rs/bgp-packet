use std::fmt;

use nom_derive::*;

use super::{CapabilityCode, Emit};

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapabilityExtendedMessage {}

impl Emit for CapabilityExtendedMessage {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::ExtendedMessage
    }
}

impl fmt::Display for CapabilityExtendedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Extended Message")
    }
}
