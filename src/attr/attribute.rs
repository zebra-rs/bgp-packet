use crate::{
    many0, parse_bgp_evpn_prefix, parse_bgp_nlri_ipv6_prefix, parse_bgp_nlri_vpnv4_prefix, Afi,
    ParseBe, RouteDistinguisher, Safi,
};
use ipnet::{Ipv4Net, Ipv6Net};
use nom::{
    bytes::complete::take,
    error::{make_error, ErrorKind},
    number::complete::{be_u128, be_u24, be_u32, be_u8},
    IResult,
};
use nom_derive::*;
use std::net::{Ipv4Addr, Ipv6Addr};

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
    pub next_hop: Option<Ipv6Addr>,
    pub ipv6_prefix: Vec<Ipv6Net>,
    pub vpnv4_prefix: Vec<Ipv4Net>,
    pub snpa: u8,
    pub evpn_prefix: Vec<Evpn>,
}

#[derive(Clone, Debug)]
pub struct MpNlriUnreachAttr {
    pub ipv6_prefix: Vec<Ipv6Net>,
    pub vpnv4_prefix: Vec<Ipv4Net>,
}

#[derive(Debug, Clone)]
pub struct Evpn {
    pub route_type: u8,
    pub rd: RouteDistinguisher,
    pub ether_tag: u32,
}

impl Evpn {
    pub fn rd(&self) -> &RouteDistinguisher {
        &self.rd
    }
}

//
pub fn parse_evpn_nlri(input: &[u8]) -> IResult<&[u8], Evpn> {
    // Following can be multiple.
    let (input, route_type) = be_u8(input)?;
    let (input, _length) = be_u8(input)?;

    match route_type {
        2 => {
            let (input, rd) = RouteDistinguisher::parse_be(input)?;

            let (input, _esi_type) = be_u8(input)?;
            let (input, _esi) = take(9usize).parse(input)?;
            let (input, ether_tag) = be_u32(input)?;

            let evpn = Evpn {
                route_type,
                rd,
                ether_tag,
            };

            let (input, _mac_len) = be_u8(input)?;
            let (input, _mac) = take(6usize).parse(input)?;

            let (input, _ip_len) = be_u8(input)?;
            // TODO parse IP address.
            let (input, _vni) = be_u24(input)?;
            Ok((input, evpn))
        }
        3 => {
            let (input, rd) = RouteDistinguisher::parse_be(input)?;
            let (input, ether_tag) = be_u32(input)?;

            let evpn = Evpn {
                route_type,
                rd,
                ether_tag,
            };

            let (input, _updates) = many0(parse_bgp_evpn_prefix).parse(input)?;

            Ok((input, evpn))
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
            let (input, _snpa) = be_u8(input)?;
            let (_, updates) = many0(parse_bgp_nlri_vpnv4_prefix).parse(input)?;
            let mp_nlri = MpNlriReachAttr {
                next_hop: None,
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
            let (input, _snpa) = be_u8(input)?;
            let (_, updates) = many0(parse_bgp_nlri_ipv6_prefix).parse(input)?;
            let mp_nlri = MpNlriReachAttr {
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
                next_hop: Some(nhop),
                evpn_prefix: evpns,
                snpa,
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
