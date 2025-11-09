use std::cell::RefCell;
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::BytesMut;
use ipnet::{Ipv4Net, Ipv6Net};
use nom::IResult;
use nom::bytes::complete::take;
use nom::combinator::peek;
use nom::error::{ErrorKind, make_error};
use nom::number::complete::{be_u8, be_u16, be_u32};
use nom_derive::*;

use crate::*;

#[repr(u8)]
#[derive(Debug, PartialEq, Clone, Copy)]
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

#[derive(NomBE, Clone)]
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
    Aggregator(Aggregator),
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
            Attr::Aggregator(v) => v.attr_emit(buf),
            Attr::Aggregator2(v) => v.attr_emit(buf),
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

impl fmt::Display for Attr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Attr::Origin(v) => write!(f, "{}", v),
            Attr::As4Path(v) => write!(f, "{}", v),
            Attr::NextHop(v) => write!(f, "{}", v),
            Attr::Med(v) => write!(f, "{}", v),
            Attr::LocalPref(v) => write!(f, "{}", v),
            Attr::AtomicAggregate(v) => write!(f, "{}", v),
            Attr::Aggregator(v) => write!(f, "{}", v),
            Attr::Aggregator2(v) => write!(f, "{}", v),
            Attr::OriginatorId(v) => write!(f, "{}", v),
            Attr::ClusterList(v) => write!(f, "{}", v),
            Attr::MpReachNlri(v) => write!(f, "{}", v),
            Attr::MpUnreachNlri(v) => write!(f, "{}", v),
            Attr::Community(v) => write!(f, "{}", v),
            Attr::ExtendedCom(v) => write!(f, "{}", v),
            Attr::PmsiTunnel(v) => write!(f, "{}", v),
            Attr::LargeCom(v) => write!(f, "{}", v),
            Attr::Aigp(v) => write!(f, "{}", v),
            _ => write!(f, "Unknown"),
        }
    }
}

impl fmt::Debug for Attr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Attr::Origin(v) => write!(f, "{:?}", v),
            Attr::As4Path(v) => write!(f, "{:?}", v),
            Attr::NextHop(v) => write!(f, "{:?}", v),
            Attr::Med(v) => write!(f, "{:?}", v),
            Attr::LocalPref(v) => write!(f, "{:?}", v),
            Attr::AtomicAggregate(v) => write!(f, "{:?}", v),
            Attr::Aggregator(v) => write!(f, "{:?}", v),
            Attr::Aggregator2(v) => write!(f, "{:?}", v),
            Attr::OriginatorId(v) => write!(f, "{:?}", v),
            Attr::ClusterList(v) => write!(f, "{:?}", v),
            Attr::MpReachNlri(v) => write!(f, "{:?}", v),
            Attr::MpUnreachNlri(v) => write!(f, "{:?}", v),
            Attr::Community(v) => write!(f, "{:?}", v),
            Attr::ExtendedCom(v) => write!(f, "{:?}", v),
            Attr::PmsiTunnel(v) => write!(f, "{:?}", v),
            Attr::LargeCom(v) => write!(f, "{:?}", v),
            Attr::Aigp(v) => write!(f, "{:?}", v),
            _ => write!(f, "Unknown"),
        }
    }
}

fn parse_bgp_attribute<'a>(
    input: &'a [u8],
    as4: bool,
    opt: &'a Option<ParseOption>,
) -> Result<(&'a [u8], Attr), BgpParseError> {
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
    if input.len() < attr_len as usize {
        return Err(BgpParseError::IncompleteData {
            needed: attr_len as usize - input.len(),
        });
    }
    let (attr_payload, input) = input.split_at(attr_len as usize);

    // Set parse context for MP_NLRI attributes
    set_parse_context((*opt).clone());

    // Parse the attribute using the appropriate selector with error context
    let (_, attr) =
        Attr::parse_be(attr_payload, AttrSelector(attr_type, as4_opt)).map_err(|e| {
            BgpParseError::AttributeParseError {
                attr_type,
                source: Box::new(BgpParseError::from(e)),
            }
        })?;

    // Clear parse context
    set_parse_context(None);

    Ok((input, attr))
}

fn parse_bgp_update_attribute(
    input: &[u8],
    length: u16,
    as4: bool,
    opt: Option<ParseOption>,
) -> Result<(&[u8], Vec<Attr>), BgpParseError> {
    let (attr, input) = input.split_at(length as usize);
    let mut remaining = attr;
    let mut attrs = Vec::new();

    while !remaining.is_empty() {
        let (new_remaining, attr) = parse_bgp_attribute(remaining, as4, &opt)?;
        attrs.push(attr);
        remaining = new_remaining;
    }

    Ok((input, attrs))
}

pub fn nlri_psize(plen: u8) -> usize {
    plen.div_ceil(8).into()
}

#[derive(Debug, Clone)]
pub struct Ipv4Nlri {
    pub id: u32,
    pub prefix: Ipv4Net,
}

#[derive(Debug, Clone)]
pub struct Ipv6Nlri {
    pub id: u32,
    pub prefix: Ipv6Net,
}

pub fn parse_ipv4_prefix(input: &[u8], add_path: bool) -> IResult<&[u8], Ipv4Nlri> {
    let (input, id) = if add_path { be_u32(input)? } else { (input, 0) };
    let (input, plen) = be_u8(input)?;
    let psize = nlri_psize(plen);
    if input.len() < psize {
        return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
    }
    let mut paddr = [0u8; 4];
    paddr[..psize].copy_from_slice(&input[..psize]);
    let (input, _) = take(psize).parse(input)?;
    let prefix = Ipv4Net::new(Ipv4Addr::from(paddr), plen).expect("Ipv4Net crete error");
    let nlri = Ipv4Nlri { id, prefix };
    Ok((input, nlri))
}

pub fn parse_bgp_nlri_ipv6_prefix(input: &[u8], add_path: bool) -> IResult<&[u8], Ipv6Nlri> {
    let (input, id) = if add_path { be_u32(input)? } else { (input, 0) };
    let (input, plen) = be_u8(input)?;
    let psize = nlri_psize(plen);
    if input.len() < psize {
        return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
    }
    let mut paddr = [0u8; 16];
    paddr[..psize].copy_from_slice(&input[..psize]);
    let (input, _) = take(psize).parse(input)?;
    let prefix = Ipv6Net::new(Ipv6Addr::from(paddr), plen).expect("Ipv6Net create error");
    let nlri = Ipv6Nlri { id, prefix };
    Ok((input, nlri))
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

    Ok((input, prefix))
}

fn parse_bgp_nlri_ipv4(input: &[u8], length: u16, add_path: bool) -> IResult<&[u8], Vec<Ipv4Nlri>> {
    let (nlri, input) = input.split_at(length as usize);
    let (_, nlris) = many0(|i| parse_ipv4_prefix(i, add_path)).parse(nlri)?;
    Ok((input, nlris))
}

#[derive(Debug, Clone)]
pub struct Vpnv4Nlri {
    pub label: Label,
    pub rd: RouteDistinguisher,
    pub nlri: Ipv4Nlri,
}

impl fmt::Display for Vpnv4Nlri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bos = if self.label.bos { "(BoS)" } else { "" };
        write!(
            f,
            "VPNv4 [{}]:[{}]{} label: {} {}",
            self.rd, self.nlri.id, self.nlri.prefix, self.label.label, bos,
        )
    }
}

pub fn parse_bgp_nlri_vpnv4_prefix(input: &[u8], add_path: bool) -> IResult<&[u8], Vpnv4Nlri> {
    let (input, id) = if add_path { be_u32(input)? } else { (input, 0) };

    // MPLS Label (3 octets) + RD (8 octets) + IPv4 Prefix (0-4 octets).
    let (input, mut plen) = be_u8(input)?;

    let psize = nlri_psize(plen);
    if input.len() < psize {
        return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
    }
    // MPLS Label.
    let (input, label) = take(3usize).parse(input)?;
    let label = Label::from(label);

    // RD.
    let (input, rd) = RouteDistinguisher::parse_be(input)?;

    // Adjust plen to MPLS Label and Route Distinguisher.
    if plen < 88 {
        // Prefix length must be >= 88.
        return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
    }
    plen -= 88;
    let psize = nlri_psize(plen);

    if psize > 4 {
        // Prefix size must be 0..=4.
        return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
    }
    if psize > input.len() {
        // Prefix size must be same or smaller than remaining input buffer.
        return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
    }

    // IPv4 prefix.
    let mut paddr = [0u8; 4];
    paddr[..psize].copy_from_slice(&input[..psize]);
    let (input, _) = take(psize).parse(input)?;
    let prefix = Ipv4Net::new(Ipv4Addr::from(paddr), plen).expect("Ipv4Net create error");

    let nlri = Ipv4Nlri { id, prefix };

    let vpnv4 = Vpnv4Nlri { label, rd, nlri };

    Ok((input, vpnv4))
}

fn parse_bgp_update_packet(
    input: &[u8],
    as4: bool,
    opt: Option<ParseOption>,
) -> Result<(&[u8], UpdatePacket), BgpParseError> {
    // AddPath receive.
    let add_path = if let Some(o) = opt.as_ref() {
        o.is_add_path_recv(Afi::Ip, Safi::Unicast)
    } else {
        false
    };
    let (input, mut packet) = UpdatePacket::parse_be(input)?;
    let (input, withdraw_len) = be_u16(input)?;
    let (input, mut withdrawal) = parse_bgp_nlri_ipv4(input, withdraw_len, add_path)?;
    packet.ipv4_withdraw.append(&mut withdrawal);
    let (input, attr_len) = be_u16(input)?;
    let (input, mut attrs) = parse_bgp_update_attribute(input, attr_len, as4, opt)?;
    packet.attrs.append(&mut attrs);
    let nlri_len = packet.header.length - BGP_HEADER_LEN - 2 - withdraw_len - 2 - attr_len;
    let (input, mut updates) = parse_bgp_nlri_ipv4(input, nlri_len, add_path)?;
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

thread_local! {
    static PARSE_CONTEXT: RefCell<Option<ParseOption>> = const { RefCell::new(None) };
}

pub fn set_parse_context(opt: Option<ParseOption>) {
    PARSE_CONTEXT.with(|ctx| {
        *ctx.borrow_mut() = opt;
    });
}

pub fn get_parse_context() -> Option<ParseOption> {
    PARSE_CONTEXT.with(|ctx| ctx.borrow().clone())
}

#[derive(Default, Debug, Clone)]
pub struct Direct {
    pub recv: bool,
    pub send: bool,
}

#[derive(Default, Debug, Clone)]
pub struct ParseOption {
    // AS4
    pub as4: Direct,
    // AddPath
    pub add_path: BTreeMap<AfiSafi, Direct>,
}

impl ParseOption {
    pub fn is_as4(&self) -> bool {
        false
    }

    pub fn is_add_path_recv(&self, afi: Afi, safi: Safi) -> bool {
        let key = AfiSafi { afi, safi };
        self.add_path.get(&key).is_some_and(|direct| direct.recv)
    }

    pub fn clear(&mut self) {
        self.as4 = Direct::default();
        self.add_path.clear();
    }
}

pub fn parse_bgp_packet(
    input: &[u8],
    as4: bool,
    opt: Option<ParseOption>,
) -> Result<(&[u8], BgpPacket), BgpParseError> {
    let (_, header) = peek(BgpHeader::parse_be).parse(input)?;
    match header.typ {
        BgpType::Open => {
            let (input, packet) = OpenPacket::parse_packet(input)?;
            Ok((input, BgpPacket::Open(packet)))
        }
        BgpType::Update => {
            let (input, p) = parse_bgp_update_packet(input, as4, opt)?;
            Ok((input, BgpPacket::Update(p)))
        }
        BgpType::Notification => {
            let (input, packet) = parse_bgp_notification_packet(input)?;
            Ok((input, BgpPacket::Notification(packet)))
        }
        BgpType::Keepalive => {
            let (input, header) = BgpHeader::parse_be(input)?;
            Ok((input, BgpPacket::Keepalive(header)))
        }
        _ => Err(BgpParseError::NomError(
            "Unknown BGP packet type".to_string(),
        )),
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
