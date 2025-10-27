use std::fmt;

use crate::*;

// BGP Attribute for quick access to each attribute. This would be used for
// consolidating route advertisement.
#[derive(Clone, Debug, Default)]
pub struct BgpAttr {
    /// Origin type
    pub origin: Option<Origin>,
    /// AS Path
    pub aspath: Option<As4Path>,
    /// Nexthop
    pub nexthop: Option<BgpNexthop>,
    /// Multi-Exit Discriminator
    pub med: Option<u32>,
    /// Local preference (IBGP only)
    pub local_pref: Option<u32>,
    /// Atomic Aggregate
    pub atomic_aggregate: Option<bool>,
    /// Aggregator.
    pub aggregator: Option<Aggregator>,
    /// Community
    pub com: Option<Community>,
    /// Originator ID
    pub originator_id: Option<OriginatorId>,
    /// Cluster List
    pub cluster_list: Option<ClusterList>,
    /// Extended Community
    pub ecom: Option<ExtCommunity>,
    /// PMSI Tunnel
    pub pmsi_tunnel: Option<PmsiTunnel>,
    /// AIGP
    pub aigp: Option<u64>,
    /// Large Community
    pub lcom: Option<LargeCommunity>,
    // TODO: Unknown Attributes.
}

impl BgpAttr {
    pub fn new() -> Self {
        BgpAttr {
            origin: Some(Origin::default()),
            aspath: Some(As4Path::default()),
            ..Default::default()
        }
    }

    pub fn from(attrs: &[Attr]) -> Self {
        let mut bgp_attr = BgpAttr::default();

        for attr in attrs.iter() {
            match attr {
                Attr::Origin(v) => {
                    bgp_attr.origin = Some(*v);
                }
                Attr::As2Path(_v) => {
                    // TODO
                }
                Attr::As4Path(v) => {
                    bgp_attr.aspath = Some(v.clone());
                }
                Attr::NextHop(v) => {
                    bgp_attr.nexthop = Some(BgpNexthop::Ipv4(v.nexthop));
                }
                Attr::Med(v) => {
                    bgp_attr.med = Some(v.med);
                }
                Attr::LocalPref(v) => {
                    bgp_attr.local_pref = Some(v.local_pref);
                }
                Attr::AtomicAggregate(_v) => {
                    bgp_attr.atomic_aggregate = Some(true);
                }
                Attr::Aggregator(v) => {
                    bgp_attr.aggregator = Some(v.clone());
                }
                Attr::Aggregator2(_v) => {
                    // TODO
                }
                Attr::Community(v) => {
                    bgp_attr.com = Some(v.clone());
                }
                Attr::OriginatorId(v) => {
                    bgp_attr.originator_id = Some(v.clone());
                }
                Attr::ClusterList(v) => {
                    bgp_attr.cluster_list = Some(v.clone());
                }
                Attr::MpReachNlri(_v) => {
                    // Ignore in attribute conversion.
                }
                Attr::MpUnreachNlri(_v) => {
                    // Ignore in attribute conversion.
                }
                Attr::ExtendedCom(v) => {
                    bgp_attr.ecom = Some(v.clone());
                }
                Attr::PmsiTunnel(v) => {
                    bgp_attr.pmsi_tunnel = Some(v.clone());
                }
                Attr::Aigp(v) => {
                    bgp_attr.aigp = Some(v.aigp);
                }
                Attr::LargeCom(v) => {
                    bgp_attr.lcom = Some(v.clone());
                }
            }
        }
        bgp_attr
    }
}

impl fmt::Display for BgpAttr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "BGP Attr:")?;
        if let Some(v) = &self.origin {
            writeln!(f, " Origin: {}", v)?;
        }
        if let Some(v) = &self.aspath {
            writeln!(f, " AS Path: {}", v)?;
        }
        if let Some(v) = &self.med {
            writeln!(f, " MED: {}", v)?;
        }
        if let Some(v) = &self.local_pref {
            writeln!(f, " LocalPref: {}", v)?;
        }
        if self.atomic_aggregate.is_some() {
            writeln!(f, " Atomic Aggregate")?;
        }
        if let Some(v) = &self.aggregator {
            writeln!(f, " {}", v)?;
        }
        if let Some(v) = &self.com {
            writeln!(f, "{}", v)?;
        }
        if let Some(v) = &self.originator_id {
            writeln!(f, " {}", v)?;
        }
        if let Some(v) = &self.cluster_list {
            writeln!(f, " {}", v)?;
        }
        if let Some(v) = &self.ecom {
            writeln!(f, " {}", v)?;
        }
        if let Some(v) = &self.pmsi_tunnel {
            writeln!(f, " {}", v)?;
        }
        if let Some(v) = &self.aigp {
            writeln!(f, " AIGP: {}", v)?;
        }
        if let Some(v) = &self.lcom {
            writeln!(f, " {}", v)?;
        }
        // Nexthop
        if let Some(v) = &self.nexthop {
            match v {
                BgpNexthop::Ipv4(v) => {
                    writeln!(f, " Nexthop: {}", v)?;
                }
                BgpNexthop::Vpnv4(v) => {
                    writeln!(f, " Nexthop: {}", v)?;
                }
            }
        }
        Ok(())
    }
}
