use std::convert::TryInto;

use super::attr::{
    Aggregator2, Aggregator4, Aigp, As2Path, As2Segment, As4Path, As4Segment, AsSegmentHeader,
    AtomicAggregate, Attribute, AttributeFlags, AttributeType, Community, ExtCommunity,
    LargeCommunity, LocalPref, Med, MpNlriAttr, MpNlriReachHeader, MpNlriUnreachHeader,
    NextHopAttr, Origin, RouteDistinguisher,
};
use super::*;
use ipnet::{Ipv4Net, Ipv6Net};
use nom::bytes::streaming::take;
use nom::combinator::{map, peek};
use nom::error::{make_error, ErrorKind};
use nom::multi::count;
use nom::number::streaming::{be_u128, be_u16, be_u32, be_u8};
use nom::IResult;
use nom_derive::*;
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr};

fn parse_bgp_attr_as2_segment(input: &[u8]) -> IResult<&[u8], As2Segment> {
    let (input, header) = AsSegmentHeader::parse(input)?;
    let (input, asns) = count(be_u16, header.length as usize)(input)?;
    let segment = As2Segment {
        typ: header.typ,
        asn: asns.into_iter().collect(),
    };
    Ok((input, segment))
}

fn parse_bgp_attr_as2_path(input: &[u8], length: u16) -> IResult<&[u8], Attribute> {
    let (attr, input) = input.split_at(length as usize);
    let (_, segs) = many0(parse_bgp_attr_as2_segment)(attr)?;
    let as_path = As2Path { segs };
    Ok((input, Attribute::As2Path(as_path)))
}

fn parse_bgp_attr_as4_segment(input: &[u8]) -> IResult<&[u8], As4Segment> {
    let (input, header) = AsSegmentHeader::parse(input)?;
    let (input, asns) = count(be_u32, header.length as usize)(input)?;
    let segment = As4Segment {
        typ: header.typ,
        asn: asns.into_iter().collect(),
    };
    Ok((input, segment))
}

fn parse_bgp_attr_as4_path(input: &[u8], length: u16) -> IResult<&[u8], Attribute> {
    let (attr, input) = input.split_at(length as usize);
    let (_, segs) = many0(parse_bgp_attr_as4_segment)(attr)?;
    let as_path = As4Path { segs: segs.into() };
    Ok((input, Attribute::As4Path(as_path)))
}

fn parse_bgp_attr_community(input: &[u8], length: u16) -> IResult<&[u8], Attribute> {
    let (attr, input) = input.split_at(length as usize);
    let (_, mut community) = Community::parse(attr)?;
    community.sort_uniq();
    Ok((input, Attribute::Community(community)))
}

fn parse_bgp_attr_mp_reach(input: &[u8], length: u16) -> IResult<&[u8], Attribute> {
    if input.len() < size_of::<MpNlriReachHeader>() {
        return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
    }
    let (attr, input) = input.split_at(length as usize);
    let (attr, header) = MpNlriReachHeader::parse(attr)?;
    if header.afi == Afi::Ip6 && header.safi == Safi::Unicast {
        if header.nhop_len != 16 {
            return Err(nom::Err::Error(make_error(input, ErrorKind::Tag)));
        }
        let (attr, nhop) = be_u128(attr)?;
        let nhop: Ipv6Addr = Ipv6Addr::from(nhop);
        let (attr, _snpa) = be_u8(attr)?;
        let (_, updates) = many0(parse_bgp_nlri_ipv6_prefix)(attr)?;
        let mp_nlri = MpNlriAttr {
            next_hop: Some(nhop),
            ipv6_prefix: updates,
            vpnv4_prefix: Vec::new(),
        };
        return Ok((input, Attribute::MpReachNlri(mp_nlri)));
    }
    if header.afi == Afi::Ip && header.safi == Safi::MplsVpn {
        println!("nhop len {}", header.nhop_len);
        // 12 = 8 + 4.
        let (attr, rd) = RouteDistinguisher::parse(attr)?;
        let (attr, nhop) = be_u32(attr)?;
        let nhop: Ipv4Addr = Ipv4Addr::from(nhop);
        println!("{}:{}", rd, nhop);
        let (attr, _snpa) = be_u8(attr)?;
        let (_, updates) = many0(parse_bgp_nlri_vpnv4_prefix)(attr)?;
        println!("{:?}", updates);
        let mp_nlri = MpNlriAttr {
            next_hop: None,
            ipv6_prefix: Vec::new(),
            vpnv4_prefix: updates,
        };
        return Ok((input, Attribute::MpReachNlri(mp_nlri)));
    }
    Err(nom::Err::Error(make_error(input, ErrorKind::Tag)))
}

fn parse_bgp_attr_mp_unreach(input: &[u8], length: u16) -> IResult<&[u8], Attribute> {
    if input.len() < size_of::<MpNlriUnreachHeader>() {
        return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
    }
    let (attr, input) = input.split_at(length as usize);
    let (attr, header) = MpNlriUnreachHeader::parse(attr)?;
    if header.afi != Afi::Ip6 || header.safi != Safi::Unicast {
        return Err(nom::Err::Error(make_error(input, ErrorKind::Tag)));
    }
    let (_, withdrawal) = many0(parse_bgp_nlri_ipv6_prefix)(attr)?;
    let mp_nlri = MpNlriAttr {
        next_hop: None,
        ipv6_prefix: withdrawal,
        vpnv4_prefix: Vec::new(),
    };
    Ok((input, Attribute::MpReachNlri(mp_nlri)))
}

fn parse_bgp_attr_large_com(input: &[u8], length: u16) -> IResult<&[u8], Attribute> {
    let (attr, input) = input.split_at(length as usize);
    let (_, lcom) = LargeCommunity::parse(attr)?;
    Ok((input, Attribute::LargeCom(lcom)))
}

fn parse_bgp_attr_ext_com(input: &[u8], length: u16) -> IResult<&[u8], Attribute> {
    let (attr, input) = input.split_at(length as usize);
    let (_, ecom) = ExtCommunity::parse(attr)?;
    Ok((input, Attribute::ExtCommunity(ecom)))
}

fn parse_bgp_attr_aigp(input: &[u8], length: u16) -> IResult<&[u8], Attribute> {
    let (attr, input) = input.split_at(length as usize);
    let (attr, typ) = be_u8(attr)?;
    if typ != 1 {
        return Err(nom::Err::Error(make_error(input, ErrorKind::Tag)));
    }
    let (attr, length) = be_u16(attr)?;
    if length != 11 {
        return Err(nom::Err::Error(make_error(input, ErrorKind::Tag)));
    }
    let (_, aigp) = Aigp::parse(attr)?;
    Ok((input, Attribute::Aigp(aigp)))
}

fn parse_bgp_attribute(input: &[u8], as4: bool) -> IResult<&[u8], Attribute> {
    let (input, flags) = be_u8(input)?;
    let flags = AttributeFlags::from_bits(flags).unwrap();
    let (input, type_code) = AttributeType::parse(input)?;
    let ext_len: usize = if flags.is_extended() { 2 } else { 1 };
    let (input, exts) = take(ext_len)(input)?;
    let attr_len = if exts.len() == 1 {
        exts[0] as u16
    } else {
        ((exts[0] as u16) << 8) + exts[1] as u16
    };
    println!("{}", type_code);
    let var_name = match type_code {
        AttributeType::Origin => map(Origin::parse, Attribute::Origin)(input),
        AttributeType::AsPath => {
            if as4 {
                parse_bgp_attr_as4_path(input, attr_len)
            } else {
                parse_bgp_attr_as2_path(input, attr_len)
            }
        }
        AttributeType::NextHop => map(NextHopAttr::parse, Attribute::NextHop)(input),
        AttributeType::Med => map(Med::parse, Attribute::Med)(input),
        AttributeType::LocalPref => map(LocalPref::parse, Attribute::LocalPref)(input),
        AttributeType::AtomicAggregate => {
            map(AtomicAggregate::parse, Attribute::AtomicAggregate)(input)
        }
        AttributeType::Aggregator => {
            if as4 {
                map(Aggregator4::parse, Attribute::Aggregator4)(input)
            } else {
                map(Aggregator2::parse, Attribute::Aggregator2)(input)
            }
        }
        AttributeType::Community => parse_bgp_attr_community(input, attr_len),
        AttributeType::MpReachNlri => parse_bgp_attr_mp_reach(input, attr_len),
        AttributeType::MpUnreachNlri => parse_bgp_attr_mp_unreach(input, attr_len),
        AttributeType::LargeCom => parse_bgp_attr_large_com(input, attr_len),
        AttributeType::ExtendedCom => parse_bgp_attr_ext_com(input, attr_len),
        AttributeType::Aigp => parse_bgp_attr_aigp(input, attr_len),
        _ => Err(nom::Err::Error(make_error(input, ErrorKind::Tag))),
    };
    var_name
}

pub fn parse_bgp_attribute_as(as4: bool) -> impl Fn(&[u8]) -> IResult<&[u8], Attribute> {
    move |i: &[u8]| parse_bgp_attribute(i, as4)
}

fn parse_bgp_update_attribute(
    input: &[u8],
    length: u16,
    as4: bool,
) -> IResult<&[u8], Vec<Attribute>> {
    let (attr, input) = input.split_at(length as usize);
    let (_, attrs) = many0(parse_bgp_attribute_as(as4))(attr)?;
    Ok((input, attrs))
}

pub fn nlri_psize(plen: u8) -> usize {
    ((plen + 7) / 8) as usize
}

pub fn parse_ipv4_prefix(input: &[u8]) -> IResult<&[u8], Ipv4Net> {
    let (input, plen) = be_u8(input)?;
    let psize = nlri_psize(plen);
    if input.len() < psize {
        return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
    }
    let mut paddr = [0u8; 4];
    paddr[..psize].copy_from_slice(&input[..psize]);
    let (input, _) = take(psize)(input)?;
    let prefix = Ipv4Net::new(Ipv4Addr::from(paddr), plen).expect("Ipv4Net crete error");
    Ok((input, prefix))
}

fn parse_bgp_nlri_ipv6_prefix(input: &[u8]) -> IResult<&[u8], Ipv6Net> {
    let (input, plen) = be_u8(input)?;
    let psize = nlri_psize(plen);
    if input.len() < psize {
        return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
    }
    let mut paddr = [0u8; 16];
    paddr[..psize].copy_from_slice(&input[..psize]);
    let (input, _) = take(psize)(input)?;
    let prefix = Ipv6Net::new(Ipv6Addr::from(paddr), plen).expect("Ipv6Net create error");
    Ok((input, prefix))
}

fn parse_bgp_nlri_ipv4(input: &[u8], length: u16) -> IResult<&[u8], Vec<Ipv4Net>> {
    let (nlri, input) = input.split_at(length as usize);
    let (_, prefix) = many0(parse_ipv4_prefix)(nlri)?;
    Ok((input, prefix))
}

fn parse_bgp_nlri_vpnv4_prefix(input: &[u8]) -> IResult<&[u8], Ipv4Net> {
    // MPLS Label (3 octets) + RD (8 octets) + IPv4 Prefix (0-4 octets).
    let (input, mut plen) = be_u8(input)?;
    let psize = nlri_psize(plen);
    if input.len() < psize {
        return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
    }
    // MPLS Label.
    let (input, label) = take(3usize)(input)?;
    println!("Label: {:?}", label);

    // RD.
    let (input, rd) = RouteDistinguisher::parse(input)?;
    println!("RD: {}", rd);

    // Adjust plen to MPLS Label and Route Distinguisher.
    plen -= 88;
    let psize = nlri_psize(plen);
    println!("plen {} psize {}", plen, psize);

    // IPv4 prefix.
    let mut paddr = [0u8; 4];
    paddr[..psize].copy_from_slice(&input[..psize]);
    let (input, _) = take(psize)(input)?;
    let prefix = Ipv4Net::new(Ipv4Addr::from(paddr), plen).expect("Ipv4Net create error");

    Ok((input, prefix))
}

fn parse_bgp_update_packet(input: &[u8], as4: bool) -> IResult<&[u8], UpdatePacket> {
    let (input, mut packet) = UpdatePacket::parse(input)?;
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
    let (input, packet) = NotificationPacket::parse(input)?;
    let len = packet.header.length - BGP_HEADER_LEN - 2;
    let (input, _data) = take(len as usize)(input)?;
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
    let (_, header) = peek(BgpHeader::parse)(input)?;
    match header.typ {
        BgpType::Open => map(OpenPacket::parse_packet, BgpPacket::Open)(input),
        BgpType::Update => {
            let (input, p) = parse_bgp_update_packet(input, as4)?;
            Ok((input, BgpPacket::Update(p)))
        }
        BgpType::Notification => map(parse_bgp_notification_packet, BgpPacket::Notification)(input),
        BgpType::Keepalive => map(BgpHeader::parse, BgpPacket::Keepalive)(input),
        _ => Err(nom::Err::Error(make_error(input, ErrorKind::Eof))),
    }
}
