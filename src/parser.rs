use std::convert::TryInto;

use super::attr::{
    Aggregator2, Aggregator4, Aigp, As2Path, As4Path, AtomicAggregate, AttributeFlags, Community,
    ExtCommunity, LargeCommunity, LocalPref, Med, MpNlriReachAttr, NexthopAttr, Origin,
    RouteDistinguisher,
};
use super::*;
use bytes::BytesMut;
use ipnet::{Ipv4Net, Ipv6Net};
use nom::bytes::streaming::take;
use nom::combinator::{map, peek};
use nom::error::{make_error, ErrorKind};
use nom::number::complete::be_u32;
//use nom::number::complete::be_u32;
use nom::number::streaming::{be_u16, be_u8};
use nom::IResult;
use nom_derive::*;
use std::net::{Ipv4Addr, Ipv6Addr};

#[repr(u8)]
#[derive(Debug, PartialEq)]
pub enum AttrType {
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
    Unknown(u8),
}

impl From<u8> for AttrType {
    fn from(attr_type: u8) -> Self {
        use AttrType::*;
        match attr_type {
            1 => Origin,
            2 => AsPath,
            3 => NextHop,
            4 => Med,
            5 => LocalPref,
            6 => AtomicAggregate,
            7 => Aggregator,
            8 => Community,
            9 => OriginatorId,
            10 => ClusterList,
            14 => MpReachNlri,
            15 => MpUnreachNlri,
            16 => ExtendedCom,
            22 => PmsiTunnel,
            25 => ExtendedIpv6Com,
            26 => Aigp,
            32 => LargeCom,
            v => Unknown(v),
        }
    }
}

impl From<AttrType> for u8 {
    fn from(attr_type: AttrType) -> Self {
        use AttrType::*;
        match attr_type {
            Origin => 1,
            AsPath => 2,
            NextHop => 3,
            Med => 4,
            LocalPref => 5,
            AtomicAggregate => 6,
            Aggregator => 7,
            Community => 8,
            OriginatorId => 9,
            ClusterList => 10,
            MpReachNlri => 14,
            MpUnreachNlri => 15,
            ExtendedCom => 16,
            PmsiTunnel => 22,
            ExtendedIpv6Com => 25,
            Aigp => 26,
            LargeCom => 32,
            Unknown(v) => v,
        }
    }
}

struct AttrSelector(AttrType, Option<bool>);

#[derive(Debug, NomBE, Clone)]
#[nom(Selector = "AttrSelector")]
pub enum Attr {
    #[nom(Selector = "AttrSelector(AttrType::Origin, None)")]
    Origin(Origin),
    #[nom(Selector = "AttrSelector(AttrType::AsPath, Some(false))")]
    As2Path(As2Path),
    #[nom(Selector = "AttrSelector(AttrType::AsPath, Some(true))")]
    As4Path(As4Path),
    #[nom(Selector = "AttrSelector(AttrType::NextHop, None)")]
    NextHop(NexthopAttr),
    #[nom(Selector = "AttrSelector(AttrType::Med, None)")]
    Med(Med),
    #[nom(Selector = "AttrSelector(AttrType::LocalPref, None)")]
    LocalPref(LocalPref),
    #[nom(Selector = "AttrSelector(AttrType::AtomicAggregate, None)")]
    AtomicAggregate(AtomicAggregate),
    #[nom(Selector = "AttrSelector(AttrType::Aggregator, Some(false))")]
    Aggregator2(Aggregator2),
    #[nom(Selector = "AttrSelector(AttrType::Aggregator, Some(true))")]
    Aggregator4(Aggregator4),
    #[nom(Selector = "AttrSelector(AttrType::Community, None)")]
    Community(Community),
    #[nom(Selector = "AttrSelector(AttrType::OriginatorId, None)")]
    OriginatorId(OriginatorId),
    #[nom(Selector = "AttrSelector(AttrType::ClusterList, None)")]
    ClusterList(ClusterList),
    #[nom(Selector = "AttrSelector(AttrType::MpReachNlri, None)")]
    MpReachNlri(MpNlriReachAttr),
    #[nom(Selector = "AttrSelector(AttrType::MpUnreachNlri, None)")]
    MpUnreachNlri(MpNlriUnreachAttr),
    #[nom(Selector = "AttrSelector(AttrType::ExtendedCom, None)")]
    ExtendedCom(ExtCommunity),
    #[nom(Selector = "AttrSelector(AttrType::PmsiTunnel, None)")]
    PmsiTunnel(PmsiTunnel),
    #[nom(Selector = "AttrSelector(AttrType::Aigp, None)")]
    Aigp(Aigp),
    #[nom(Selector = "AttrSelector(AttrType::LargeCom, None)")]
    LargeCom(LargeCommunity),
}

impl Attr {
    pub fn emit(&self, buf: &mut BytesMut) {
        match self {
            Attr::Origin(v) => v.attr_emit(buf),
            Attr::As4Path(v) => v.attr_emit(buf),
            Attr::NextHop(v) => v.attr_emit(buf),
            Attr::Med(v) => v.attr_emit(buf),
            Attr::LocalPref(v) => v.attr_emit(buf),
            Attr::AtomicAggregate(v) => v.attr_emit(buf),
            Attr::Aggregator2(v) => v.attr_emit(buf),
            Attr::Aggregator4(v) => v.attr_emit(buf),
            Attr::OriginatorId(v) => v.attr_emit(buf),
            Attr::ClusterList(v) => v.attr_emit(buf),
            // Attr::MpReachNlri(v) => v.attr_emit(buf),
            Attr::Community(v) => v.attr_emit(buf),
            Attr::ExtendedCom(v) => v.attr_emit(buf),
            Attr::PmsiTunnel(v) => v.attr_emit(buf),
            Attr::LargeCom(v) => v.attr_emit(buf),
            Attr::Aigp(v) => v.attr_emit(buf),
            _ => {
                //
            }
        }
    }
}

fn parse_bgp_attribute(input: &[u8], as4: bool) -> IResult<&[u8], Attr> {
    // Parse the attribute flags and type code
    let (input, flags_byte) = be_u8(input)?;
    let flags = AttributeFlags::from_bits(flags_byte).unwrap();
    let (input, attr_type_byte) = be_u8(input)?;
    let attr_type: AttrType = attr_type_byte.into();

    // Decide extended length presence and parse length
    let (input, length_bytes) = if flags.is_extended() {
        take(2usize).parse(input)?
    } else {
        take(1usize).parse(input)?
    };
    let attr_len = u16::from_be_bytes(if length_bytes.len() == 2 {
        [length_bytes[0], length_bytes[1]]
    } else {
        [0, length_bytes[0]]
    });

    // Only AS_PATH or AGGREGATOR care about as4 extension
    let as4_opt = matches!(attr_type, AttrType::AsPath | AttrType::Aggregator).then_some(as4);

    // Split out the payload for this attribute
    let (attr_payload, input) = input.split_at(attr_len as usize);

    // Parse the attribute using the appropriate selector (may use as4 option)
    println!("Attr Type: {:?}", attr_type);
    let (_, attr) = Attr::parse_be(attr_payload, AttrSelector(attr_type, as4_opt))?;

    Ok((input, attr))
}

fn parse_bgp_update_attribute(input: &[u8], length: u16, as4: bool) -> IResult<&[u8], Vec<Attr>> {
    let (attr, input) = input.split_at(length as usize);
    let (_, attrs) = many0(|i| parse_bgp_attribute(i, as4)).parse(attr)?;
    Ok((input, attrs))
}

pub fn nlri_psize(plen: u8) -> usize {
    plen.div_ceil(8).into()
}

pub fn parse_ipv4_prefix(input: &[u8]) -> IResult<&[u8], Ipv4Net> {
    let (input, plen) = be_u8(input)?;
    let psize = nlri_psize(plen);
    if input.len() < psize {
        return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
    }
    let mut paddr = [0u8; 4];
    paddr[..psize].copy_from_slice(&input[..psize]);
    let (input, _) = take(psize).parse(input)?;
    let prefix = Ipv4Net::new(Ipv4Addr::from(paddr), plen).expect("Ipv4Net crete error");
    Ok((input, prefix))
}

pub fn parse_bgp_nlri_ipv6_prefix(input: &[u8]) -> IResult<&[u8], Ipv6Net> {
    let (input, plen) = be_u8(input)?;
    let psize = nlri_psize(plen);
    if input.len() < psize {
        return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
    }
    let mut paddr = [0u8; 16];
    paddr[..psize].copy_from_slice(&input[..psize]);
    let (input, _) = take(psize).parse(input)?;
    let prefix = Ipv6Net::new(Ipv6Addr::from(paddr), plen).expect("Ipv6Net create error");
    Ok((input, prefix))
}

pub fn parse_bgp_evpn_prefix(input: &[u8]) -> IResult<&[u8], Ipv6Net> {
    let (input, plen) = be_u8(input)?;
    let psize = nlri_psize(plen);
    if input.len() < psize {
        return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
    }
    let mut paddr = [0u8; 16];
    paddr[..psize].copy_from_slice(&input[..psize]);
    let (input, _) = take(psize).parse(input)?;
    let prefix = Ipv6Net::new(Ipv6Addr::from(paddr), plen).expect("Ipv6Net create error");
    println!("IPv6 prefix: {}", prefix);

    Ok((input, prefix))
}

fn parse_bgp_nlri_ipv4(input: &[u8], length: u16) -> IResult<&[u8], Vec<Ipv4Net>> {
    let (nlri, input) = input.split_at(length as usize);
    let (_, prefix) = many0(parse_ipv4_prefix).parse(nlri)?;
    Ok((input, prefix))
}

pub fn parse_bgp_nlri_vpnv4_prefix(input: &[u8]) -> IResult<&[u8], Ipv4Net> {
    // MPLS Label (3 octets) + RD (8 octets) + IPv4 Prefix (0-4 octets).
    let (input, mut plen) = be_u8(input)?;
    let psize = nlri_psize(plen);
    if input.len() < psize {
        return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
    }
    // MPLS Label.
    let (input, label) = take(3usize).parse(input)?;
    println!("Label: {:?}", label);

    // RD.
    let (input, rd) = RouteDistinguisher::parse_be(input)?;
    println!("RD: {}", rd);

    // Adjust plen to MPLS Label and Route Distinguisher.
    plen -= 88;
    let psize = nlri_psize(plen);
    println!("plen {} psize {}", plen, psize);

    // IPv4 prefix.
    let mut paddr = [0u8; 4];
    paddr[..psize].copy_from_slice(&input[..psize]);
    let (input, _) = take(psize).parse(input)?;
    let prefix = Ipv4Net::new(Ipv4Addr::from(paddr), plen).expect("Ipv4Net create error");

    Ok((input, prefix))
}

fn parse_bgp_update_packet(input: &[u8], as4: bool) -> IResult<&[u8], UpdatePacket> {
    let (input, mut packet) = UpdatePacket::parse_be(input)?;
    let (input, withdraw_len) = be_u16(input)?;
    let (input, mut withdrawal) = parse_bgp_nlri_ipv4(input, withdraw_len)?;
    packet.ipv4_withdraw.append(&mut withdrawal);
    let (input, attr_len) = be_u16(input)?;
    let (input, mut attrs) = parse_bgp_update_attribute(input, attr_len, as4)?;
    packet.attrs.append(&mut attrs);
    let nlri_len = packet.header.length - BGP_HEADER_LEN - 2 - withdraw_len - 2 - attr_len;
    let (input, mut updates) = parse_bgp_nlri_ipv4(input, nlri_len)?;
    packet.ipv4_update.append(&mut updates);
    Ok((input, packet))
}

fn parse_bgp_notification_packet(input: &[u8]) -> IResult<&[u8], NotificationPacket> {
    let (input, packet) = NotificationPacket::parse_be(input)?;
    let len = packet.header.length - BGP_HEADER_LEN - 2;
    let (input, _data) = take(len as usize).parse(input)?;
    Ok((input, packet))
}

pub fn peek_bgp_length(input: &[u8]) -> usize {
    if let Some(len) = input.get(16..18) {
        u16::from_be_bytes(len.try_into().unwrap()) as usize
    } else {
        0
    }
}

pub fn parse_bgp_packet(input: &[u8], as4: bool) -> IResult<&[u8], BgpPacket> {
    let (_, header) = peek(BgpHeader::parse_be).parse(input)?;
    match header.typ {
        BgpType::Open => map(OpenPacket::parse_packet, BgpPacket::Open).parse(input),
        BgpType::Update => {
            let (input, p) = parse_bgp_update_packet(input, as4)?;
            Ok((input, BgpPacket::Update(p)))
        }
        BgpType::Notification => map(parse_bgp_notification_packet, BgpPacket::Notification).parse(input),
        BgpType::Keepalive => map(BgpHeader::parse_be, BgpPacket::Keepalive).parse(input),
        _ => Err(nom::Err::Error(make_error(input, ErrorKind::Eof))),
    }
}

impl ParseBe<Ipv4Addr> for Ipv4Addr {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        if input.len() < 4 {
            return Err(nom::Err::Incomplete(nom::Needed::new(4)));
        }
        let (input, addr) = be_u32(input)?;
        Ok((input, Self::from(addr)))
    }
}

pub fn u32_u8_3(value: u32) -> [u8; 3] {
    // Extract the three least significant bytes as big-endian
    [
        (value >> 16) as u8, // Most significant byte of the remaining 3 bytes
        (value >> 8) as u8,  // Middle byte
        value as u8,         // Least significant byte
    ]
}
