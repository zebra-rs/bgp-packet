use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{BufMut, BytesMut};
use ipnet::Ipv6Net;
use nom::{
    IResult,
    bytes::complete::take,
    error::{ErrorKind, make_error},
    number::complete::{be_u8, be_u24, be_u32, be_u128},
};
use nom_derive::*;

use crate::attrs::emitter::AttrEmitter;
use crate::{
    Afi, AttrFlags, AttrType, ExtCommunityValue, Ipv4Nlri, Ipv6Nlri, ParseBe, ParseNlri,
    ParseOption, RouteDistinguisher, Safi, Vpnv4Nlri, get_parse_context, many0, nlri_psize,
};

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

#[derive(Debug, Clone)]
pub struct Rtcv4 {
    pub id: u32,
    pub asn: u32,
    pub rt: ExtCommunityValue,
}

impl ParseNlri<Rtcv4> for Rtcv4 {
    fn parse_nlri(input: &[u8], addpath: bool) -> IResult<&[u8], Rtcv4> {
        let (input, id) = if addpath { be_u32(input)? } else { (input, 0) };
        let (input, plen) = be_u8(input)?;
        if plen != 96 {
            return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
        }
        let (input, asn) = be_u32(input)?;
        let (input, rt) = ExtCommunityValue::parse_be(input)?;
        let nlri = Rtcv4 { id, asn, rt };
        Ok((input, nlri))
    }
}

#[derive(Clone)]
pub enum MpNlriReachAttr {
    Ipv4 {
        snpa: u8,
        nhop: IpAddr,
        updates: Vec<Ipv4Nlri>,
    },
    Ipv6 {
        snpa: u8,
        nhop: IpAddr,
        updates: Vec<Ipv6Nlri>,
    },
    Vpnv4 {
        snpa: u8,
        nhop: Vpnv4Nexthop,
        updates: Vec<Vpnv4Nlri>,
    },
    // Vpnv6 {
    //     //
    // },
    Evpn {
        snpa: u8,
        nhop: IpAddr,
        updates: Vec<EvpnRoute>,
    },
    Rtcv4 {
        snpa: u8,
        nhop: IpAddr,
        updates: Vec<Rtcv4>,
    },
}

impl MpNlriReachAttr {
    pub fn attr_emit(&self, buf: &mut BytesMut) {
        match self {
            MpNlriReachAttr::Vpnv4 {
                snpa,
                nhop,
                updates,
            } => {
                let attr = Vpnv4Reach {
                    snpa: *snpa,
                    nhop: nhop.clone(),
                    updates: updates.clone(),
                };
                attr.attr_emit(buf);
            }
            _ => {
                //
            }
        }
    }
}

#[derive(Clone)]
pub enum MpNlriUnreachAttr {
    // Ipv4Nlri(Vec<>),
    Ipv4Eor,
    Ipv6Nlri(Vec<Ipv6Nlri>),
    Ipv6Eor,
    Vpnv4(Vec<Vpnv4Nlri>),
    Vpnv4Eor,
    // Vpnv6,
    // Vpnv6Eor,
    Evpn(Vec<EvpnRoute>),
    EvpnEor,
    Rtcv4(Vec<Rtcv4>),
    Rtcv4Eor,
}

impl MpNlriUnreachAttr {
    pub fn attr_emit(&self, buf: &mut BytesMut) {
        match self {
            MpNlriUnreachAttr::Vpnv4(withdraw) => {
                let attr = Vpnv4Unreach {
                    withdraw: withdraw.clone(),
                };
                attr.attr_emit(buf);
            }
            MpNlriUnreachAttr::Vpnv4Eor => {
                let attr = Vpnv4Unreach { withdraw: vec![] };
                attr.attr_emit(buf);
            }
            _ => {
                //
            }
        }
    }
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

impl ParseNlri<EvpnRoute> for EvpnRoute {
    fn parse_nlri(input: &[u8], addpath: bool) -> IResult<&[u8], EvpnRoute> {
        let (input, id) = if addpath { be_u32(input)? } else { (input, 0) };
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
                    return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
                }
                let (input, mac) = take(6usize).parse(input)?;
                let (input, ip_len) = be_u8(input)?;
                let ip_size = nlri_psize(ip_len);
                let (input, _) = if ip_size != 0 {
                    take(ip_size).parse(input)?
                } else {
                    (input, &[] as &[u8])
                };
                let (input, vni) = be_u24(input)?;

                let mut evpn = EvpnMac {
                    id,
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

                let (input, updates) = many0(Ipv6Net::parse_be).parse(input)?;
                let evpn = EvpnMulticast {
                    rd,
                    ether_tag,
                    updates,
                };

                Ok((input, EvpnRoute::Multicast(evpn)))
            }
            _ => Err(nom::Err::Error(make_error(input, ErrorKind::NoneOf))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EvpnMac {
    pub id: u32,
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

#[derive(Debug, Clone)]
pub struct Vpnv4Nexthop {
    pub rd: RouteDistinguisher,
    pub nhop: Ipv4Addr,
}

impl fmt::Display for Vpnv4Nexthop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}]:{}", self.rd, self.nhop)
    }
}

pub struct Vpnv4Reach {
    pub snpa: u8,
    pub nhop: Vpnv4Nexthop,
    pub updates: Vec<Vpnv4Nlri>,
}

impl AttrEmitter for Vpnv4Reach {
    fn attr_type(&self) -> AttrType {
        AttrType::MpReachNlri
    }

    fn attr_flags(&self) -> AttrFlags {
        AttrFlags::new().with_optional(true)
    }

    fn len(&self) -> Option<usize> {
        None
    }

    fn emit(&self, buf: &mut BytesMut) {
        // AFI/SAFI.
        buf.put_u16(u16::from(Afi::Ip));
        buf.put_u8(u8::from(Safi::MplsVpn));
        // Nexthop
        buf.put_u8(12); // Nexthop length.  RD(8)+IPv4 Nexthop(4);
        // Nexthop RD.
        let rd = [0u8; 8];
        buf.put(&rd[..]);
        // Nexthop.
        buf.put(&self.nhop.nhop.octets()[..]);
        // SNPA
        buf.put_u8(0);
        // Prefix.
        for update in self.updates.iter() {
            // AddPath
            if update.nlri.id != 0 {
                buf.put_u32(update.nlri.id);
            }
            // Plen
            let plen = update.nlri.prefix.prefix_len() + 88;
            buf.put_u8(plen);
            // Label
            buf.put(&update.label.to_bytes()[..]);
            // RD
            buf.put_u16(update.rd.typ.clone() as u16);
            buf.put(&update.rd.val[..]);
            // Prefix
            let plen = nlri_psize(update.nlri.prefix.prefix_len());
            buf.put(&update.nlri.prefix.addr().octets()[0..plen]);
        }
    }
}

pub struct Vpnv4Unreach {
    pub withdraw: Vec<Vpnv4Nlri>,
}

impl AttrEmitter for Vpnv4Unreach {
    fn attr_type(&self) -> AttrType {
        AttrType::MpUnreachNlri
    }

    fn attr_flags(&self) -> AttrFlags {
        AttrFlags::new().with_optional(true)
    }

    fn len(&self) -> Option<usize> {
        None
    }

    fn emit(&self, buf: &mut BytesMut) {
        // AFI/SAFI.
        buf.put_u16(u16::from(Afi::Ip));
        buf.put_u8(u8::from(Safi::MplsVpn));
        // Prefix.
        for withdraw in self.withdraw.iter() {
            // AddPath
            if withdraw.nlri.id != 0 {
                buf.put_u32(withdraw.nlri.id);
            }
            // Plen
            let plen = withdraw.nlri.prefix.prefix_len() + 88;
            buf.put_u8(plen);
            // Label
            buf.put(&withdraw.label.to_bytes()[..]);
            // RD
            buf.put_u16(withdraw.rd.typ.clone() as u16);
            buf.put(&withdraw.rd.val[..]);
            // Prefix
            let plen = nlri_psize(withdraw.nlri.prefix.prefix_len());
            buf.put(&withdraw.nlri.prefix.addr().octets()[0..plen]);
        }
    }
}

impl MpNlriReachAttr {
    pub fn parse_nlri_opt(input: &[u8], opt: Option<ParseOption>) -> nom::IResult<&[u8], Self> {
        if input.len() < size_of::<MpNlriReachHeader>() {
            return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
        }
        let (input, header) = MpNlriReachHeader::parse_be(input)?;
        let add_path = if let Some(o) = opt {
            o.is_add_path_recv(header.afi, header.safi)
        } else {
            false
        };
        if header.afi == Afi::Ip && header.safi == Safi::MplsVpn {
            let (input, rd) = RouteDistinguisher::parse_be(input)?;
            let (input, nhop) = be_u32(input)?;
            let nhop: Ipv4Addr = Ipv4Addr::from(nhop);
            let nhop = Vpnv4Nexthop { rd, nhop };
            let (input, snpa) = be_u8(input)?;
            let (_, updates) = many0(|i| Vpnv4Nlri::parse_nlri(i, add_path)).parse(input)?;
            let mp_nlri = MpNlriReachAttr::Vpnv4 {
                snpa,
                nhop,
                updates,
            };
            return Ok((input, mp_nlri));
        }
        if header.afi == Afi::Ip6 && header.safi == Safi::Unicast {
            if header.nhop_len != 16 {
                return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
            }
            let (input, nhop) = be_u128(input)?;
            let nhop = IpAddr::V6(Ipv6Addr::from(nhop));
            let (input, snpa) = be_u8(input)?;
            let (_, updates) = many0(|i| Ipv6Nlri::parse_nlri(i, add_path)).parse(input)?;
            let mp_nlri = MpNlriReachAttr::Ipv6 {
                snpa,
                nhop,
                updates,
            };
            return Ok((input, mp_nlri));
        }
        if header.afi == Afi::L2vpn && header.safi == Safi::Evpn {
            // Nexthop can be IPv4 or IPv6 address.
            if header.nhop_len != 4 && header.nhop_len != 16 {
                return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
            }
            let (input, nhop) = if header.nhop_len == 4 {
                let (input, addr) = be_u32(input)?;
                let nhop: IpAddr = IpAddr::V4(Ipv4Addr::from(addr));
                (input, nhop)
            } else {
                let (input, addr) = be_u128(input)?;
                let nhop: IpAddr = IpAddr::V6(Ipv6Addr::from(addr));
                (input, nhop)
            };
            let (input, snpa) = be_u8(input)?;

            // EVPN
            let (input, updates) = many0(|i| EvpnRoute::parse_nlri(i, add_path)).parse(input)?;

            let mp_nlri = MpNlriReachAttr::Evpn {
                snpa,
                nhop,
                updates,
            };
            return Ok((input, mp_nlri));
        }
        if header.afi == Afi::Ip && header.safi == Safi::Rtc {
            // Nexthop can be IPv4 or IPv6 address.
            if header.nhop_len != 4 && header.nhop_len != 16 {
                return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
            }
            let (input, nhop) = if header.nhop_len == 4 {
                let (input, addr) = be_u32(input)?;
                let nhop: IpAddr = IpAddr::V4(Ipv4Addr::from(addr));
                (input, nhop)
            } else {
                let (input, addr) = be_u128(input)?;
                let nhop: IpAddr = IpAddr::V6(Ipv6Addr::from(addr));
                (input, nhop)
            };
            let (input, snpa) = be_u8(input)?;
            let (input, updates) = many0(|i| Rtcv4::parse_nlri(i, add_path)).parse(input)?;
            let rtc_nlri = MpNlriReachAttr::Rtcv4 {
                snpa,
                nhop,
                updates,
            };
            return Ok((input, rtc_nlri));
        }
        Err(nom::Err::Error(make_error(input, ErrorKind::NoneOf)))
    }
}

impl MpNlriUnreachAttr {
    pub fn parse_nlri_opt(input: &[u8], opt: Option<ParseOption>) -> nom::IResult<&[u8], Self> {
        // AFI + SAFI = 3.
        if input.len() < 3 {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                ErrorKind::Verify,
            )));
        }
        let (input, header) = MpNlriUnreachHeader::parse_be(input)?;
        let add_path = if let Some(o) = opt {
            o.is_add_path_recv(header.afi, header.safi)
        } else {
            false
        };
        if header.afi == Afi::Ip && header.safi == Safi::MplsVpn {
            if input.is_empty() {
                let mp_nlri = MpNlriUnreachAttr::Vpnv4Eor;
                return Ok((input, mp_nlri));
            }
            let (input, withdrawal) = many0(|i| Vpnv4Nlri::parse_nlri(i, add_path)).parse(input)?;
            let mp_nlri = MpNlriUnreachAttr::Vpnv4(withdrawal);
            return Ok((input, mp_nlri));
        }
        if header.afi == Afi::Ip6 && header.safi == Safi::Unicast {
            if input.is_empty() {
                let mp_nlri = MpNlriUnreachAttr::Ipv6Eor;
                return Ok((input, mp_nlri));
            }
            let (input, withdrawal) = many0(|i| Ipv6Nlri::parse_nlri(i, add_path)).parse(input)?;
            let mp_nlri = MpNlriUnreachAttr::Ipv6Nlri(withdrawal);
            return Ok((input, mp_nlri));
        }
        if header.afi == Afi::L2vpn && header.safi == Safi::Evpn {
            if input.is_empty() {
                let mp_nlri = MpNlriUnreachAttr::EvpnEor;
                return Ok((input, mp_nlri));
            }
            let (input, evpns) = many0(|i| EvpnRoute::parse_nlri(i, add_path)).parse(input)?;
            let mp_nlri = MpNlriUnreachAttr::Evpn(evpns);
            return Ok((input, mp_nlri));
        }
        if header.afi == Afi::Ip && header.safi == Safi::Rtc {
            if input.is_empty() {
                let mp_nlri = MpNlriUnreachAttr::Rtcv4Eor;
                return Ok((input, mp_nlri));
            }
            let (input, rtcv4) = many0(|i| Rtcv4::parse_nlri(i, add_path)).parse(input)?;
            let mp_nlri = MpNlriUnreachAttr::Rtcv4(rtcv4);
            return Ok((input, mp_nlri));
        }
        Err(nom::Err::Error(make_error(input, ErrorKind::NoneOf)))
    }
}

// ParseBe implementations that read from thread-local context
impl ParseBe<MpNlriReachAttr> for MpNlriReachAttr {
    fn parse_be(input: &[u8]) -> nom::IResult<&[u8], Self> {
        let opt = get_parse_context();
        Self::parse_nlri_opt(input, opt)
    }
}

impl ParseBe<MpNlriUnreachAttr> for MpNlriUnreachAttr {
    fn parse_be(input: &[u8]) -> nom::IResult<&[u8], Self> {
        let opt = get_parse_context();
        Self::parse_nlri_opt(input, opt)
    }
}

impl fmt::Display for MpNlriReachAttr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use MpNlriReachAttr::*;
        match self {
            Ipv6 {
                snpa: _,
                nhop,
                updates,
            } => {
                for update in updates.iter() {
                    writeln!(f, "{}:{} => {}", update.id, update.prefix, nhop)?;
                }
            }
            Vpnv4 {
                snpa: _,
                nhop,
                updates,
            } => {
                for update in updates.iter() {
                    writeln!(
                        f,
                        "{}:{}:{} => {}",
                        update.nlri.id, update.rd, update.nlri.prefix, nhop
                    )?;
                }
            }
            Evpn {
                snpa: _,
                nhop,
                updates,
            } => {
                for update in updates.iter() {
                    match update {
                        EvpnRoute::Mac(v) => {
                            write!(
                                f,
                                "RD: {}, VNI: {}, MAC: {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x} => {}",
                                v.rd,
                                v.vni,
                                v.mac[0],
                                v.mac[1],
                                v.mac[2],
                                v.mac[3],
                                v.mac[4],
                                v.mac[5],
                                nhop,
                            )?;
                        }
                        EvpnRoute::Multicast(v) => {
                            write!(f, "RD: {}", v.rd)?;
                            for update in v.updates.iter() {
                                write!(f, " {} => {}", update, nhop)?;
                            }
                        }
                    }
                }
            }
            _ => {
                //
            }
        }
        Ok(())
    }
}

impl fmt::Display for MpNlriUnreachAttr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use MpNlriUnreachAttr::*;
        match self {
            Ipv4Eor => {
                write!(f, "EoR: {}/{}", Afi::Ip, Safi::Unicast)
            }
            Ipv6Nlri(ipv6_nlris) => {
                for ipv6 in ipv6_nlris.iter() {
                    writeln!(f, "{}:{}", ipv6.id, ipv6.prefix)?;
                }
                Ok(())
            }
            Ipv6Eor => {
                write!(f, "EoR: {}/{}", Afi::Ip6, Safi::Unicast)
            }
            Vpnv4(vpnv4_nlris) => {
                for vpnv4 in vpnv4_nlris.iter() {
                    writeln!(f, "{}:{}:{}", vpnv4.nlri.id, vpnv4.rd, vpnv4.nlri.prefix)?;
                }
                Ok(())
            }
            Vpnv4Eor => {
                write!(f, "EoR: {}/{}", Afi::Ip, Safi::MplsVpn)
            }
            Evpn(evpn_routes) => {
                for evpn in evpn_routes.iter() {
                    match evpn {
                        EvpnRoute::Mac(v) => {
                            write!(
                                f,
                                "RD: {}, VNI: {}, MAC: {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                                v.rd,
                                v.vni,
                                v.mac[0],
                                v.mac[1],
                                v.mac[2],
                                v.mac[3],
                                v.mac[4],
                                v.mac[5],
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
            EvpnEor => {
                write!(f, "EoR: {}/{}", Afi::L2vpn, Safi::Evpn)
            }
            Rtcv4(rtcv4s) => {
                for rtcv4 in rtcv4s {
                    write!(f, "ASN:{} {}", rtcv4.asn, rtcv4.rt)?;
                }
                Ok(())
            }
            Rtcv4Eor => {
                write!(f, "EoR: {}/{}", Afi::Ip, Safi::Rtc)
            }
        }
    }
}

impl fmt::Debug for MpNlriReachAttr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl fmt::Debug for MpNlriUnreachAttr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}
