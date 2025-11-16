use std::collections::BTreeMap;

use crate::{
    AddPathValue, AfiSafi, CapAs4, CapDynamic, CapEnhancedRefresh, CapExtended, CapFqdn,
    CapMultiProtocol, CapRefresh, CapRefreshCisco, CapVersion, LLGRValue, PathLimitValue,
    RestartValue,
};

#[derive(Default)]
pub struct BgpCap {
    pub mp: BTreeMap<AfiSafi, CapMultiProtocol>,
    pub refresh: Option<CapRefresh>,
    pub refresh_cisco: Option<CapRefreshCisco>,
    pub enhanced_refresh: Option<CapEnhancedRefresh>,
    pub extended: Option<CapExtended>,
    pub restart: BTreeMap<AfiSafi, RestartValue>,
    pub as4: Option<CapAs4>,
    pub dynamic: Option<CapDynamic>,
    pub addpath: BTreeMap<AfiSafi, AddPathValue>,
    pub llgr: BTreeMap<AfiSafi, LLGRValue>,
    pub fqdn: Option<CapFqdn>,
    pub version: Option<CapVersion>,
    pub path_limit: BTreeMap<AfiSafi, PathLimitValue>,
}
