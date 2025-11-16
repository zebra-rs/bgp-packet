use std::fmt;
use std::net::Ipv4Addr;

use bytes::{BufMut, BytesMut};
use ipnet::Ipv6Net;
use nom::{
    IResult,
    bytes::complete::take,
    error::{ErrorKind, make_error},
    number::complete::{be_u8, be_u24, be_u32},
};
use nom_derive::*;

use crate::attrs::emitter::AttrEmitter;
use crate::{
    Afi, AttrFlags, AttrType, ExtCommunityValue, ParseBe, ParseNlri, RouteDistinguisher, Safi,
    Vpnv4Nlri, many0, nlri_psize,
};

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
