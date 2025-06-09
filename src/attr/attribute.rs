use crate::{
    many0, parse_bgp_evpn_prefix, parse_bgp_nlri_ipv6_prefix, parse_bgp_nlri_vpnv4_prefix, Afi,
    ParseBe, RouteDistinguisher, Safi,
};
use bytes::{BufMut, BytesMut};
use ipnet::{Ipv4Net, Ipv6Net};
use nom::{
    bytes::complete::take,
    error::{make_error, ErrorKind},
    number::complete::{be_u128, be_u24, be_u32, be_u8},
    IResult,
};
use nom_derive::*;
use rusticata_macros::newtype_enum;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::{
    Aggregator2, Aggregator4, Aigp, As2Path, As4Path, AtomicAggregate, AttributeFlags, ClusterList,
    Community, ExtCommunity, ExtIpv6Community, LargeCommunity, LocalPref, Med, NexthopAttr, Origin,
    OriginatorId, PmsiTunnel,
};

#[derive(Debug, Eq, PartialEq, NomBE, Clone)]
pub struct AttributeType(pub u8);

newtype_enum! {
    impl display AttributeType {
        Origin = 1,
        AsPath = 2,
        NextHop = 3,
        Med = 4,
        LocalPref = 5,
        AtomicAggregate = 6,
        Aggregator = 7,
        Community = 8,
        OriginatorId = 9,
        ClusterList = 10,
        MpReachNlri = 14,
        MpUnreachNlri = 15,
        ExtendedCom = 16,
        PmsiTunnel = 22,
        ExtendedIpv6Com = 25,
        Aigp = 26,
        LargeCom = 32,
    }
}

#[derive(Clone, Debug)]
pub enum Attribute {
    Origin(Origin),
    As2Path(As2Path),
    As4Path(As4Path),
    NextHop(NexthopAttr),
    Med(Med),
    LocalPref(LocalPref),
    AtomicAggregate(AtomicAggregate),
    Aggregator2(Aggregator2),
    Aggregator4(Aggregator4),
    Community(Community),
    OriginatorId(OriginatorId),
    ClusterList(ClusterList),
    MpReachNlri(MpNlriReachAttr),
    MpUnreachNlri(MpNlriUnreachAttr),
    ExtCommunity(ExtCommunity),
    PmsiTunnel(PmsiTunnel),
    ExtIpv6Community(ExtIpv6Community),
    Aigp(Aigp),
    LargeCom(LargeCommunity),
}

pub trait AttributeEncoder {
    fn attr_type() -> AttributeType;
    fn attr_flag() -> AttributeFlags;
}

pub fn encode_tlv<T: AttributeEncoder>(buf: &mut BytesMut, attr_buf: BytesMut) {
    if attr_buf.len() > 255 {
        buf.put_u8(T::attr_flag().bits() | AttributeFlags::EXTENDED.bits());
        buf.put_u8(T::attr_type().0);
        buf.put_u16(attr_buf.len() as u16)
    } else {
        buf.put_u8(T::attr_flag().bits());
        buf.put_u8(T::attr_type().0);
        buf.put_u8(attr_buf.len() as u8);
    }
    buf.put(&attr_buf[..]);
}

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

#[derive(Clone, Debug)]
pub struct MpNlriReachAttr {
    pub next_hop: Option<Ipv6Addr>,
    pub ipv6_prefix: Vec<Ipv6Net>,
    pub vpnv4_prefix: Vec<Ipv4Net>,
}

#[derive(Clone, Debug)]
pub struct MpNlriUnreachAttr {
    pub ipv6_prefix: Vec<Ipv6Net>,
    pub vpnv4_prefix: Vec<Ipv4Net>,
}

#[derive(Debug)]
pub struct Evpn {
    pub route_type: u8,
    pub rd: RouteDistinguisher,
    pub ether_tag: u32,
}

//
pub fn parse_evpn_nlri(input: &[u8]) -> IResult<&[u8], Evpn> {
    // Following can be multiple.
    let (input, route_type) = be_u8(input)?;
    let (input, length) = be_u8(input)?;
    println!("XXX route_type: {}", route_type);
    println!("XXX length: {}", length);

    match route_type {
        2 => {
            println!("XXX MAC Advertisement Route");

            let (input, rd) = RouteDistinguisher::parse(input)?;
            println!("RD: {}", rd);

            let (input, esi_type) = be_u8(input)?;
            println!("ESI type: {}", esi_type);
            let (input, esi) = take(9usize)(input)?;
            println!("ESI: {:?}", esi);
            let (input, ether_tag) = be_u32(input)?;
            println!("ether_tag: {:?}", ether_tag);

            let evpn = Evpn {
                route_type,
                rd,
                ether_tag,
            };
            println!("EVPN: {:?}", evpn);

            let (input, mac_len) = be_u8(input)?;
            let (input, mac) = take(6usize)(input)?;
            println!("mac_len: {}", mac_len);
            println!("mac: {:?}", mac);

            let (input, _ip_len) = be_u8(input)?;
            // TODO parse IP address.
            let (input, vni) = be_u24(input)?;
            println!("vni: {:?}", vni);
            return Ok((input, evpn));
        }
        3 => {
            let (input, rd) = RouteDistinguisher::parse(input)?;
            let (input, ether_tag) = be_u32(input)?;

            let evpn = Evpn {
                route_type,
                rd,
                ether_tag,
            };
            println!("EVPN: {:?}", evpn);

            let (input, _updates) = many0(parse_bgp_evpn_prefix)(input)?;

            return Ok((input, evpn));
        }
        _ => {
            return Err(nom::Err::Error(make_error(input, ErrorKind::Tag)));
        }
    }
}

impl ParseBe<MpNlriReachAttr> for MpNlriReachAttr {
    fn parse_be(input: &[u8]) -> nom::IResult<&[u8], Self> {
        if input.len() < size_of::<MpNlriReachHeader>() {
            return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
        }
        let (input, header) = MpNlriReachHeader::parse(input)?;
        println!("{:?}", header);
        if header.afi == Afi::Ip && header.safi == Safi::MplsVpn {
            println!("nhop len {}", header.nhop_len);
            // 12 = 8 + 4.
            let (input, rd) = RouteDistinguisher::parse(input)?;
            let (input, nhop) = be_u32(input)?;
            let nhop: Ipv4Addr = Ipv4Addr::from(nhop);
            println!("{}:{}", rd, nhop);
            let (input, _snpa) = be_u8(input)?;
            let (_, updates) = many0(parse_bgp_nlri_vpnv4_prefix)(input)?;
            println!("{:?}", updates);
            let mp_nlri = MpNlriReachAttr {
                next_hop: None,
                ipv6_prefix: Vec::new(),
                vpnv4_prefix: updates,
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
            let (_, updates) = many0(parse_bgp_nlri_ipv6_prefix)(input)?;
            let mp_nlri = MpNlriReachAttr {
                next_hop: Some(nhop),
                ipv6_prefix: updates,
                vpnv4_prefix: Vec::new(),
            };
            return Ok((input, mp_nlri));
        }
        if header.afi == Afi::L2vpn && header.safi == Safi::Evpn {
            println!("nhop len {}", header.nhop_len);
            if header.nhop_len != 16 {
                return Err(nom::Err::Error(make_error(input, ErrorKind::Tag)));
            }
            let (input, nhop) = be_u128(input)?;
            let nhop: Ipv6Addr = Ipv6Addr::from(nhop);
            let (input, _snpa) = be_u8(input)?;

            // EVPN
            let (input, evpns) = many0(parse_evpn_nlri)(input)?;
            println!("{:?}", evpns);

            let mp_nlri = MpNlriReachAttr {
                next_hop: Some(nhop),
                ipv6_prefix: Vec::new(),
                vpnv4_prefix: Vec::new(),
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
        let (input, header) = MpNlriUnreachHeader::parse(input)?;
        if header.afi != Afi::Ip6 || header.safi != Safi::Unicast {
            return Err(nom::Err::Error(make_error(input, ErrorKind::Tag)));
        }
        let (_, withdrawal) = many0(parse_bgp_nlri_ipv6_prefix)(input)?;
        let mp_nlri = MpNlriUnreachAttr {
            ipv6_prefix: withdrawal,
            vpnv4_prefix: Vec::new(),
        };
        Ok((input, mp_nlri))
    }
}
