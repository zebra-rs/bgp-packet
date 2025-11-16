use std::cell::RefCell;
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};
use nom::IResult;
use nom::bytes::complete::take;
use nom::combinator::peek;
use nom::error::{ErrorKind, make_error};
use nom::number::complete::{be_u8, be_u16, be_u32};
use nom_derive::*;

use crate::*;

pub fn nlri_psize(plen: u8) -> usize {
    plen.div_ceil(8).into()
}

#[derive(Debug, Clone)]
pub struct Ipv4Nlri {
    pub id: u32,
    pub prefix: Ipv4Net,
}

impl ParseNlri<Ipv4Nlri> for Ipv4Nlri {
    fn parse_nlri(input: &[u8], add_path: bool) -> IResult<&[u8], Ipv4Nlri> {
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
}

fn parse_bgp_nlri_ipv4(input: &[u8], length: u16, add_path: bool) -> IResult<&[u8], Vec<Ipv4Nlri>> {
    let (nlri, input) = input.split_at(length as usize);
    let (_, nlris) = many0(|i| Ipv4Nlri::parse_nlri(i, add_path)).parse(nlri)?;
    Ok((input, nlris))
}

#[derive(Debug, Clone)]
pub struct Ipv6Nlri {
    pub id: u32,
    pub prefix: Ipv6Net,
}

impl ParseNlri<Ipv6Nlri> for Ipv6Nlri {
    fn parse_nlri(input: &[u8], add_path: bool) -> IResult<&[u8], Ipv6Nlri> {
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
}

impl ParseBe<Ipv6Net> for Ipv6Net {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Ipv6Net> {
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
}

#[derive(Debug, Clone)]
pub struct Vpnv4Nlri {
    pub label: Label,
    pub rd: RouteDistinguisher,
    pub nlri: Ipv4Nlri,
}

#[derive(Debug, Clone)]
pub struct Vpnv6Nlri {
    pub label: Label,
    pub rd: RouteDistinguisher,
    pub nlri: Ipv6Nlri,
}

impl ParseNlri<Vpnv4Nlri> for Vpnv4Nlri {
    fn parse_nlri(input: &[u8], add_path: bool) -> IResult<&[u8], Vpnv4Nlri> {
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

impl UpdatePacket {
    pub fn parse_packet(
        input: &[u8],
        as4: bool,
        opt: Option<ParseOption>,
    ) -> Result<(&[u8], UpdatePacket), BgpParseError> {
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
        let (input, _, bgp_attr, mp_update, mp_withdraw) =
            parse_bgp_update_attribute(input, attr_len, as4, opt)?;
        packet.bgp_attr = Some(bgp_attr);
        packet.mp_update = mp_update;
        packet.mp_withdraw = mp_withdraw;
        let nlri_len = packet.header.length - BGP_HEADER_LEN - 2 - withdraw_len - 2 - attr_len;
        let (input, mut updates) = parse_bgp_nlri_ipv4(input, nlri_len, add_path)?;
        packet.ipv4_update.append(&mut updates);
        Ok((input, packet))
    }
}

impl NotificationPacket {
    pub fn parse_packet(input: &[u8]) -> IResult<&[u8], NotificationPacket> {
        let (input, packet) = NotificationPacket::parse_be(input)?;
        let len = packet.header.length - BGP_HEADER_LEN - 2;
        let (input, _data) = take(len as usize).parse(input)?;
        Ok((input, packet))
    }
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

    pub fn is_add_path_send(&self, afi: Afi, safi: Safi) -> bool {
        let key = AfiSafi { afi, safi };
        self.add_path.get(&key).is_some_and(|direct| direct.send)
    }

    pub fn clear(&mut self) {
        self.as4 = Direct::default();
        self.add_path.clear();
    }
}

impl BgpPacket {
    pub fn parse_packet(
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
                let (input, p) = UpdatePacket::parse_packet(input, as4, opt)?;
                Ok((input, BgpPacket::Update(Box::new(p))))
            }
            BgpType::Notification => {
                let (input, packet) = NotificationPacket::parse_packet(input)?;
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
}
