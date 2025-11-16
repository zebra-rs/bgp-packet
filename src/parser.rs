use std::cell::RefCell;
use std::collections::BTreeMap;
use std::convert::TryInto;

use nom::IResult;
use nom::bytes::complete::take;
use nom::combinator::peek;
use nom::number::complete::be_u16;
use nom_derive::*;

use crate::*;

pub fn nlri_psize(plen: u8) -> usize {
    plen.div_ceil(8).into()
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
