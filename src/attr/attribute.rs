use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{
    Afi, ParseBe, RouteDistinguisher, Safi, many0, nlri_psize, parse_bgp_evpn_prefix,
    parse_bgp_nlri_ipv6_prefix, parse_bgp_nlri_vpnv4_prefix,
};
use ipnet::{Ipv4Net, Ipv6Net};
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

#[derive(Clone, Default)]
pub struct MpNlriReachAttr {
    pub snpa: u8,
    pub next_hop: Option<Ipv6Addr>,
    pub ipv6_prefix: Vec<Ipv6Net>,
    pub vpnv4_prefix: Vec<Ipv4Net>,
    pub evpn_prefix: Vec<EvpnRoute>,
}

#[derive(Clone, Debug)]
pub struct MpNlriUnreachAttr {
    pub ipv6_prefix: Vec<Ipv6Net>,
    pub vpnv4_prefix: Vec<Ipv4Net>,
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

impl ParseBe<MpNlriReachAttr> for MpNlriReachAttr {
    fn parse_be(input: &[u8]) -> nom::IResult<&[u8], Self> {
        if input.len() < size_of::<MpNlriReachHeader>() {
            return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
        }
        let (input, header) = MpNlriReachHeader::parse_be(input)?;
        if header.afi == Afi::Ip && header.safi == Safi::MplsVpn {
            // 12 = 8 + 4.
            let (input, _rd) = RouteDistinguisher::parse_be(input)?;
            let (input, nhop) = be_u32(input)?;
            let _nhop: Ipv4Addr = Ipv4Addr::from(nhop);
            let (input, snpa) = be_u8(input)?;
            let (_, updates) = many0(parse_bgp_nlri_vpnv4_prefix).parse(input)?;
            let mp_nlri = MpNlriReachAttr {
                snpa,
                vpnv4_prefix: updates,
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
                next_hop: Some(nhop),
                ipv6_prefix: updates,
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
                next_hop: Some(nhop),
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
        if input.len() < size_of::<MpNlriUnreachHeader>() {
            return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
        }
        let (input, header) = MpNlriUnreachHeader::parse_be(input)?;
        if header.afi != Afi::Ip6 || header.safi != Safi::Unicast {
            return Err(nom::Err::Error(make_error(input, ErrorKind::Tag)));
        }
        let (_, withdrawal) = many0(parse_bgp_nlri_ipv6_prefix).parse(input)?;
        let mp_nlri = MpNlriUnreachAttr {
            ipv6_prefix: withdrawal,
            vpnv4_prefix: Vec::new(),
        };
        Ok((input, mp_nlri))
    }
}

impl fmt::Display for MpNlriReachAttr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for evpn in self.evpn_prefix.iter() {
            match evpn {
                EvpnRoute::Mac(v) => {
                    write!(
                        f,
                        "\n  RD: {}, VNI: {}, MAC: {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                        v.rd, v.vni, v.mac[0], v.mac[1], v.mac[2], v.mac[3], v.mac[4], v.mac[5],
                    )?;
                }
                EvpnRoute::Multicast(v) => {
                    write!(f, "\n  RD: {}", v.rd)?;
                    for update in v.updates.iter() {
                        write!(f, " {}", update)?;
                    }
                }
            }
        }
        Ok(())
    }
}

impl fmt::Debug for MpNlriReachAttr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, " MP Reach:{}", self)
    }
}
