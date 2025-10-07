use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{
    Afi, ParseBe, RouteDistinguisher, Safi, Vpnv4Net, many0, nlri_psize, parse_bgp_evpn_prefix,
    parse_bgp_nlri_ipv6_prefix, parse_bgp_nlri_vpnv4_prefix,
};
use ipnet::Ipv6Net;
use nom::{
    IResult,
    bytes::complete::take,
    error::{ErrorKind, make_error},
    number::complete::{be_u8, be_u24, be_u32, be_u128},
};
use nom_derive::*;

#[derive(Clone, Debug, NomBE)]
pub struct MpNlriReachHeader {
    pub afi: Afi,
    pub safi: Safi,
    pub nhop_len: u8,
}

#[derive(Clone, Debug, NomBE)]
pub struct MpNlriUnreachHeader {
    pub afi: Afi,
    pub safi: Safi,
}

#[derive(Clone, Debug, Default)]
pub struct MpNlriReachAttr {
    pub snpa: u8,
    pub ipv6_prefix: Vec<Ipv6Net>,
    pub ipv6_nexthop: Option<Ipv6Addr>,
    pub vpnv4_prefix: Vec<Vpnv4Net>,
    pub vpnv4_nexthop: Option<Vpnv4Nexthop>,
    pub evpn_prefix: Vec<EvpnRoute>,
}

#[derive(Clone, Debug, Default)]
pub struct MpNlriUnreachAttr {
    pub ipv6_prefix: Vec<Ipv6Net>,
    pub ipv6_eor: bool,
    pub vpnv4_prefix: Vec<Vpnv4Net>,
    pub vpnv4_eor: bool,
    pub evpn_prefix: Vec<EvpnRoute>,
    pub evpn_eor: bool,
}

#[derive(Debug, Clone)]
pub enum EvpnRouteType {
    EthernetAd,    // 1
    MacIpAdvRoute, // 2
    IncMulticast,  // 3
    EthernetSr,    // 4
    Unknown(u8),
}

impl From<EvpnRouteType> for u8 {
    fn from(val: EvpnRouteType) -> u8 {
        use EvpnRouteType::*;
        match val {
            EthernetAd => 1,
            MacIpAdvRoute => 2,
            IncMulticast => 3,
            EthernetSr => 4,
            Unknown(val) => val,
        }
    }
}

impl From<u8> for EvpnRouteType {
    fn from(val: u8) -> Self {
        use EvpnRouteType::*;
        match val {
            1 => EthernetAd,
            2 => MacIpAdvRoute,
            3 => IncMulticast,
            4 => EthernetSr,
            _ => Unknown(val),
        }
    }
}

#[derive(Debug)]
pub struct Evpn {
    pub route_type: EvpnRouteType,
    pub rd: RouteDistinguisher,
    pub ether_tag: u32,
}

#[derive(Debug, Clone)]
pub enum EvpnRoute {
    Mac(EvpnMac),
    Multicast(EvpnMulticast),
}

#[derive(Debug, Clone)]
pub struct EvpnMac {
    pub rd: RouteDistinguisher,
    pub esi_type: u8,
    pub ether_tag: u32,
    pub mac: [u8; 6],
    pub vni: u32,
}

#[derive(Debug, Clone)]
pub struct EvpnMulticast {
    pub rd: RouteDistinguisher,
    pub ether_tag: u32,
    pub updates: Vec<Ipv6Net>,
}

impl Evpn {
    pub fn rd(&self) -> &RouteDistinguisher {
        &self.rd
    }
}

pub fn parse_evpn_nlri(input: &[u8]) -> IResult<&[u8], EvpnRoute> {
    let (input, typ) = be_u8(input)?;
    let route_type: EvpnRouteType = typ.into();
    let (input, _length) = be_u8(input)?;

    use EvpnRouteType::*;
    match route_type {
        MacIpAdvRoute => {
            let (input, rd) = RouteDistinguisher::parse_be(input)?;

            let (input, esi_type) = be_u8(input)?;
            let (input, _esi) = take(9usize).parse(input)?;
            let (input, ether_tag) = be_u32(input)?;

            let (input, mac_len) = be_u8(input)?;
            let mac_size = nlri_psize(mac_len);
            if mac_size != 6 {
                return Err(nom::Err::Error(make_error(input, ErrorKind::Tag)));
            }
            let (input, mac) = take(6usize).parse(input)?;
            let (input, ip_len) = be_u8(input)?;
            let ip_size = nlri_psize(ip_len);
            if ip_size != 0 {
                // TODO parse IP address.
            }
            let (input, vni) = be_u24(input)?;

            let mut evpn = EvpnMac {
                rd,
                esi_type,
                ether_tag,
                mac: [0u8; 6],
                vni,
            };
            evpn.mac.copy_from_slice(mac);

            Ok((input, EvpnRoute::Mac(evpn)))
        }
        IncMulticast => {
            let (input, rd) = RouteDistinguisher::parse_be(input)?;
            let (input, ether_tag) = be_u32(input)?;

            let (input, updates) = many0(parse_bgp_evpn_prefix).parse(input)?;
            let evpn = EvpnMulticast {
                rd,
                ether_tag,
                updates,
            };

            Ok((input, EvpnRoute::Multicast(evpn)))
        }
        _ => Err(nom::Err::Error(make_error(input, ErrorKind::Tag))),
    }
}

#[derive(Debug, Clone)]
pub struct Vpnv4Nexthop {
    rd: RouteDistinguisher,
    nhop: Ipv4Addr,
}

impl fmt::Display for Vpnv4Nexthop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}]:{}", self.rd, self.nhop)
    }
}

impl ParseBe<MpNlriReachAttr> for MpNlriReachAttr {
    fn parse_be(input: &[u8]) -> nom::IResult<&[u8], Self> {
        if input.len() < size_of::<MpNlriReachHeader>() {
            return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
        }
        let (input, header) = MpNlriReachHeader::parse_be(input)?;
        if header.afi == Afi::Ip && header.safi == Safi::MplsVpn {
            let (input, rd) = RouteDistinguisher::parse_be(input)?;
            let (input, nhop) = be_u32(input)?;
            let nhop: Ipv4Addr = Ipv4Addr::from(nhop);
            let nhop = Vpnv4Nexthop { rd, nhop };
            let (input, snpa) = be_u8(input)?;
            let (_, updates) = many0(parse_bgp_nlri_vpnv4_prefix).parse(input)?;
            let mp_nlri = MpNlriReachAttr {
                snpa,
                vpnv4_prefix: updates,
                vpnv4_nexthop: Some(nhop),
                ..Default::default()
            };
            return Ok((input, mp_nlri));
        }
        if header.afi == Afi::Ip6 && header.safi == Safi::Unicast {
            if header.nhop_len != 16 {
                return Err(nom::Err::Error(make_error(input, ErrorKind::Tag)));
            }
            let (input, nhop) = be_u128(input)?;
            let nhop: Ipv6Addr = Ipv6Addr::from(nhop);
            let (input, snpa) = be_u8(input)?;
            let (_, updates) = many0(parse_bgp_nlri_ipv6_prefix).parse(input)?;
            let mp_nlri = MpNlriReachAttr {
                snpa,
                ipv6_prefix: updates,
                ipv6_nexthop: Some(nhop),
                ..Default::default()
            };
            return Ok((input, mp_nlri));
        }
        if header.afi == Afi::L2vpn && header.safi == Safi::Evpn {
            // Nexthop can be IPv4 or IPv6 address.
            if header.nhop_len != 4 && header.nhop_len != 16 {
                return Err(nom::Err::Error(make_error(input, ErrorKind::Tag)));
            }
            let (input, nhop) = be_u128(input)?;
            let nhop: Ipv6Addr = Ipv6Addr::from(nhop);
            let (input, snpa) = be_u8(input)?;

            // EVPN
            let (input, evpns) = many0(parse_evpn_nlri).parse(input)?;

            let mp_nlri = MpNlriReachAttr {
                snpa,
                ipv6_nexthop: Some(nhop),
                evpn_prefix: evpns,
                ..Default::default()
            };
            return Ok((input, mp_nlri));
        }
        Err(nom::Err::Error(make_error(input, ErrorKind::Tag)))
    }
}

impl ParseBe<MpNlriUnreachAttr> for MpNlriUnreachAttr {
    fn parse_be(input: &[u8]) -> nom::IResult<&[u8], Self> {
        // AFI + SAFI = 3.
        if input.len() < 3 {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                ErrorKind::Verify,
            )));
        }
        let (input, header) = MpNlriUnreachHeader::parse_be(input)?;
        //
        if header.afi == Afi::Ip && header.safi == Safi::MplsVpn {
            if input.is_empty() {
                let mp_nlri = MpNlriUnreachAttr {
                    vpnv4_eor: true,
                    ..Default::default()
                };
                return Ok((input, mp_nlri));
            }
            let (input, withdrawal) = many0(parse_bgp_nlri_vpnv4_prefix).parse(input)?;
            let mp_nlri = MpNlriUnreachAttr {
                vpnv4_prefix: withdrawal,
                ..Default::default()
            };
            return Ok((input, mp_nlri));
        }
        if header.afi == Afi::Ip6 && header.safi == Safi::Unicast {
            if input.is_empty() {
                let mp_nlri = MpNlriUnreachAttr {
                    ipv6_eor: true,
                    ..Default::default()
                };
                return Ok((input, mp_nlri));
            }
            let (input, withdrawal) = many0(parse_bgp_nlri_ipv6_prefix).parse(input)?;
            let mp_nlri = MpNlriUnreachAttr {
                ipv6_prefix: withdrawal,
                ..Default::default()
            };
            return Ok((input, mp_nlri));
        }
        if header.afi == Afi::L2vpn && header.safi == Safi::Evpn {
            if input.is_empty() {
                let mp_nlri = MpNlriUnreachAttr {
                    evpn_eor: true,
                    ..Default::default()
                };
                return Ok((input, mp_nlri));
            }
            let (input, evpns) = many0(parse_evpn_nlri).parse(input)?;
            let mp_nlri = MpNlriUnreachAttr {
                evpn_prefix: evpns,
                ..Default::default()
            };
            return Ok((input, mp_nlri));
        }
        Err(nom::Err::Error(make_error(input, ErrorKind::Tag)))
    }
}

impl fmt::Display for MpNlriReachAttr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.vpnv4_prefix.is_empty() {
            for vpn in self.vpnv4_prefix.iter() {
                write!(f, "{}", vpn)?;
            }
            if let Some(nhop) = &self.vpnv4_nexthop {
                write!(f, " Nexthop: {}", nhop)?;
            }
        }
        for evpn in self.evpn_prefix.iter() {
            match evpn {
                EvpnRoute::Mac(v) => {
                    write!(
                        f,
                        "RD: {}, VNI: {}, MAC: {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                        v.rd, v.vni, v.mac[0], v.mac[1], v.mac[2], v.mac[3], v.mac[4], v.mac[5],
                    )?;
                }
                EvpnRoute::Multicast(v) => {
                    write!(f, "RD: {}", v.rd)?;
                    for update in v.updates.iter() {
                        write!(f, " {}", update)?;
                    }
                }
            }
        }
        Ok(())
    }
}

impl fmt::Display for MpNlriUnreachAttr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.vpnv4_eor {
            write!(f, "EoR: AFI:IP, SAFI:MPLS_VPN")?;
        }
        if self.ipv6_eor {
            write!(f, "EoR: AFI:IP6, SAFI:UNICAST")?;
        }
        if self.evpn_eor {
            write!(f, "EoR: AFI:L2VPN, SAFI:EVPN")?;
        }
        for evpn in self.evpn_prefix.iter() {
            match evpn {
                EvpnRoute::Mac(v) => {
                    write!(
                        f,
                        "RD: {}, VNI: {}, MAC: {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                        v.rd, v.vni, v.mac[0], v.mac[1], v.mac[2], v.mac[3], v.mac[4], v.mac[5],
                    )?;
                }
                EvpnRoute::Multicast(v) => {
                    write!(f, "RD: {}", v.rd)?;
                    for update in v.updates.iter() {
                        write!(f, " {}", update)?;
                    }
                }
            }
        }
        Ok(())
    }
}
