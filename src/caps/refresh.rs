use std::fmt;

use nom_derive::*;

use super::{CapCode, Emit};

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapRefresh {}

impl Emit for CapRefresh {
    fn code(&self) -> CapCode {
        CapCode::RouteRefresh
    }
}

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapRefreshCisco {}

impl Emit for CapRefreshCisco {
    fn code(&self) -> CapCode {
        CapCode::RouteRefreshCisco
    }
}

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapEnhancedRefresh {}

impl Emit for CapEnhancedRefresh {
    fn code(&self) -> CapCode {
        CapCode::EnhancedRouteRefresh
    }
}

impl fmt::Display for CapRefresh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Route Refresh")
    }
}

impl fmt::Display for CapRefreshCisco {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RouteRefresh (Cisco)")
    }
}

impl fmt::Display for CapEnhancedRefresh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Enhanced Route Refresh")
    }
}
