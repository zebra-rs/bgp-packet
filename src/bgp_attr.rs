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
    pub med: Option<Med>,
    /// Local preference (IBGP only)
    pub local_pref: Option<LocalPref>,
    /// Atomic Aggregate
    pub atomic_aggregate: Option<AtomicAggregate>,
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
            med: Some(Med::default()),
            ..Default::default()
        }
    }

    pub fn to(&self) -> Vec<Attr> {
        let mut attrs = Vec::new();

        if let Some(v) = &self.origin {
            attrs.push(Attr::Origin(*v));
        }
        if let Some(v) = &self.aspath {
            attrs.push(Attr::As4Path(v.clone()));
        }
        if let Some(v) = &self.nexthop {
            match v {
                BgpNexthop::Ipv4(addr) => {
                    attrs.push(Attr::NextHop(NexthopAttr { nexthop: *addr }));
                }
                BgpNexthop::Vpnv4(_) => {
                    // VPNv4 nexthop is handled via MpReachNlri, not NextHop attribute
                }
            }
        }
        if let Some(v) = &self.med {
            attrs.push(Attr::Med(v.clone()));
        }
        if let Some(v) = &self.local_pref {
            attrs.push(Attr::LocalPref(v.clone()));
        }
        if let Some(v) = &self.atomic_aggregate {
            attrs.push(Attr::AtomicAggregate(v.clone()));
        }
        if let Some(v) = &self.aggregator {
            attrs.push(Attr::Aggregator(v.clone()));
        }
        if let Some(v) = &self.com {
            attrs.push(Attr::Community(v.clone()));
        }
        if let Some(v) = &self.originator_id {
            attrs.push(Attr::OriginatorId(v.clone()));
        }
        if let Some(v) = &self.cluster_list {
            attrs.push(Attr::ClusterList(v.clone()));
        }
        if let Some(v) = &self.ecom {
            attrs.push(Attr::ExtendedCom(v.clone()));
        }
        if let Some(v) = &self.pmsi_tunnel {
            attrs.push(Attr::PmsiTunnel(v.clone()));
        }
        if let Some(v) = &self.aigp {
            attrs.push(Attr::Aigp(Aigp { aigp: *v }));
        }
        if let Some(v) = &self.lcom {
            attrs.push(Attr::LargeCom(v.clone()));
        }

        attrs
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
                    bgp_attr.med = Some(v.clone());
                }
                Attr::LocalPref(v) => {
                    bgp_attr.local_pref = Some(v.clone());
                }
                Attr::AtomicAggregate(v) => {
                    bgp_attr.atomic_aggregate = Some(v.clone());
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_bgp_attr_to_from_roundtrip() {
        // Create a BgpAttr with various attributes
        let mut bgp_attr = BgpAttr::new();
        bgp_attr.nexthop = Some(BgpNexthop::Ipv4(Ipv4Addr::new(192, 168, 1, 1)));
        bgp_attr.local_pref = Some(LocalPref { local_pref: 100 });
        bgp_attr.com = Some(Community(vec![
            CommunityValue::from_readable_str("100:200").unwrap().0,
        ]));

        // Convert to Vec<Attr>
        let attrs = bgp_attr.to();

        // Verify we have the expected attributes
        assert!(attrs.iter().any(|a| matches!(a, Attr::Origin(_))));
        assert!(attrs.iter().any(|a| matches!(a, Attr::As4Path(_))));
        assert!(attrs.iter().any(|a| matches!(a, Attr::NextHop(_))));
        assert!(attrs.iter().any(|a| matches!(a, Attr::Med(_))));
        assert!(attrs.iter().any(|a| matches!(a, Attr::LocalPref(_))));
        assert!(attrs.iter().any(|a| matches!(a, Attr::Community(_))));

        // Convert back to BgpAttr
        let bgp_attr2 = BgpAttr::from(&attrs);

        // Verify round-trip
        assert_eq!(
            bgp_attr.origin.unwrap().to_string(),
            bgp_attr2.origin.unwrap().to_string()
        );
        assert_eq!(
            bgp_attr.aspath.as_ref().unwrap().to_string(),
            bgp_attr2.aspath.as_ref().unwrap().to_string()
        );
        assert_eq!(
            bgp_attr.local_pref.as_ref().unwrap().local_pref,
            bgp_attr2.local_pref.as_ref().unwrap().local_pref
        );
    }

    #[test]
    fn test_bgp_attr_new() {
        let bgp_attr = BgpAttr::new();
        assert!(bgp_attr.origin.is_some());
        assert!(bgp_attr.aspath.is_some());
        assert!(bgp_attr.med.is_some());
        assert_eq!(bgp_attr.origin.unwrap(), Origin::Igp);
        assert_eq!(bgp_attr.aspath.unwrap().length(), 0);
    }

    #[test]
    fn test_bgp_attr_to_empty() {
        let bgp_attr = BgpAttr::default();
        let attrs = bgp_attr.to();
        assert_eq!(attrs.len(), 0);
    }
}
