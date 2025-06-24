use std::fmt;

use nom_derive::*;

use super::{CapabilityCode, Emit};

#[derive(Default, PartialEq, NomBE, Clone)]
pub struct CapabilityRouteRefresh {}

impl Emit for CapabilityRouteRefresh {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::RouteRefresh
    }
}

#[derive(Default, PartialEq, NomBE, Clone)]
pub struct CapabilityRouteRefreshCisco {}

impl Emit for CapabilityRouteRefreshCisco {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::RouteRefreshCisco
    }
}

#[derive(Default, PartialEq, NomBE, Clone)]
pub struct CapabilityEnhancedRouteRefresh {}

impl Emit for CapabilityEnhancedRouteRefresh {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::EnhancedRouteRefresh
    }
}

impl fmt::Debug for CapabilityRouteRefresh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RouteRefresh")
    }
}

impl fmt::Debug for CapabilityRouteRefreshCisco {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RouteRefresh (Cisco)")
    }
}

impl fmt::Debug for CapabilityEnhancedRouteRefresh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Enhanced RouteRefresh")
    }
}
