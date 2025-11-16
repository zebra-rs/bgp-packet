use std::fmt;

use nom_derive::*;

use super::{CapabilityCode, Emit};

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapabilityRouteRefresh {}

impl Emit for CapabilityRouteRefresh {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::RouteRefresh
    }
}

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapabilityRouteRefreshCisco {}

impl Emit for CapabilityRouteRefreshCisco {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::RouteRefreshCisco
    }
}

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapabilityEnhancedRouteRefresh {}

impl Emit for CapabilityEnhancedRouteRefresh {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::EnhancedRouteRefresh
    }
}

impl fmt::Display for CapabilityRouteRefresh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Route Refresh")
    }
}

impl fmt::Display for CapabilityRouteRefreshCisco {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RouteRefresh (Cisco)")
    }
}

impl fmt::Display for CapabilityEnhancedRouteRefresh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Enhanced Route Refresh")
    }
}
