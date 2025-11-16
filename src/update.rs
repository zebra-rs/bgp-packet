use std::fmt;

use bytes::{BufMut, BytesMut};
use nom_derive::*;

use crate::{
    BGP_HEADER_LEN, BgpAttr, BgpHeader, BgpType, Ipv4Nlri, MpNlriReachAttr, MpNlriUnreachAttr,
    nlri_psize,
};

#[derive(NomBE)]
pub struct UpdatePacket {
    pub header: BgpHeader,
    #[nom(Ignore)]
    pub bgp_attr: Option<BgpAttr>,
    #[nom(Ignore)]
    pub ipv4_update: Vec<Ipv4Nlri>,
    #[nom(Ignore)]
    pub ipv4_withdraw: Vec<Ipv4Nlri>,
    #[nom(Ignore)]
    pub mp_update: Option<MpNlriReachAttr>,
    #[nom(Ignore)]
    pub mp_withdraw: Option<MpNlriUnreachAttr>,
}

impl UpdatePacket {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for UpdatePacket {
    fn default() -> Self {
        Self {
            header: BgpHeader::new(BgpType::Update, BGP_HEADER_LEN),
            bgp_attr: None,
            ipv4_update: Vec::new(),
            ipv4_withdraw: Vec::new(),
            mp_update: None,
            mp_withdraw: None,
        }
    }
}

impl From<UpdatePacket> for BytesMut {
    fn from(update: UpdatePacket) -> Self {
        let mut buf = BytesMut::new();
        let header: BytesMut = update.header.into();
        buf.put(&header[..]);

        // IPv4 unicast withdraw.
        let withdraw_len_pos = buf.len();
        buf.put_u16(0u16); // Placeholder.
        let withdraw_pos: std::ops::Range<usize> = withdraw_len_pos..withdraw_len_pos + 2;
        for ip in update.ipv4_withdraw.iter() {
            if ip.id != 0 {
                buf.put_u32(ip.id);
            }
            buf.put_u8(ip.prefix.prefix_len());
            let plen = nlri_psize(ip.prefix.prefix_len());
            buf.put(&ip.prefix.addr().octets()[0..plen]);
        }
        let withdraw_len: u16 = (buf.len() - withdraw_len_pos - 2) as u16;
        buf[withdraw_pos].copy_from_slice(&withdraw_len.to_be_bytes());

        // Attributes length.
        let attr_len_pos = buf.len();
        buf.put_u16(0u16); // Placeholder
        let attr_pos: std::ops::Range<usize> = attr_len_pos..attr_len_pos + 2;

        // Attributes emit.
        if let Some(bgp_attr) = update.bgp_attr {
            bgp_attr.attr_emit(&mut buf);
        }

        // MP reach.
        if let Some(mp_update) = update.mp_update {
            mp_update.attr_emit(&mut buf);
        }

        // MP reach.
        if let Some(mp_withdraw) = update.mp_withdraw {
            mp_withdraw.attr_emit(&mut buf);
        }

        let attr_len: u16 = (buf.len() - attr_len_pos - 2) as u16;
        buf[attr_pos].copy_from_slice(&attr_len.to_be_bytes());

        // IPv4 unicast update.
        for ip in update.ipv4_update.iter() {
            if ip.id != 0 {
                buf.put_u32(ip.id);
            }
            buf.put_u8(ip.prefix.prefix_len());
            let plen = nlri_psize(ip.prefix.prefix_len());
            buf.put(&ip.prefix.addr().octets()[0..plen]);
        }

        const LENGTH_POS: std::ops::Range<usize> = 16..18;
        let length: u16 = buf.len() as u16;
        buf[LENGTH_POS].copy_from_slice(&length.to_be_bytes());

        buf
    }
}

impl fmt::Debug for UpdatePacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Update Message:")?;
        if let Some(bgp_attr) = &self.bgp_attr {
            write!(f, "{}", bgp_attr)?;
        }
        if !self.ipv4_update.is_empty() {
            write!(f, "\n IPv4 Updates:")?;
            for update in self.ipv4_update.iter() {
                write!(f, "\n  {}", update.prefix)?;
            }
        }
        if !self.ipv4_withdraw.is_empty() {
            write!(f, "\n IPv4 Withdraw:")?;
            for withdraw in self.ipv4_withdraw.iter() {
                write!(f, "\n  {}", withdraw.prefix)?;
            }
        }
        Ok(())
    }
}
