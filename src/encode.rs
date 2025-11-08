use std::net::Ipv4Addr;

use bytes::{BufMut, BytesMut};

use crate::{Afi, AttrEmitter, AttrFlags, AttrType, Safi, Vpnv4Nexthop, Vpnv4Nlri, nlri_psize};

use super::{BgpHeader, NotificationPacket, OpenPacket, UpdatePacket};

impl From<BgpHeader> for BytesMut {
    fn from(header: BgpHeader) -> Self {
        let mut buf = BytesMut::new();
        buf.put(&header.marker[..]);
        buf.put_u16(header.length);
        let typ: u8 = header.typ as u8;
        buf.put_u8(typ);
        buf
    }
}

impl From<OpenPacket> for BytesMut {
    fn from(open: OpenPacket) -> Self {
        let mut buf = BytesMut::new();
        let header: BytesMut = open.header.into();
        buf.put(&header[..]);
        buf.put_u8(open.version);
        buf.put_u16(open.asn);
        buf.put_u16(open.hold_time);
        buf.put(&open.bgp_id[..]);

        // Opt param buffer.
        let mut opt_buf = BytesMut::new();
        for cap in open.caps.iter() {
            cap.encode(&mut opt_buf);
        }

        // Extended opt param length as defined in RFC9072.
        let opt_param_len = opt_buf.len();
        if opt_param_len < 255 {
            buf.put_u8(opt_param_len as u8);
        } else {
            buf.put_u8(255u8);
            buf.put_u8(255u8);
            buf.put_u16(opt_param_len as u16);
        }
        buf.put(&opt_buf[..]);

        const LENGTH_POS: std::ops::Range<usize> = 16..18;
        let length: u16 = buf.len() as u16;
        buf[LENGTH_POS].copy_from_slice(&length.to_be_bytes());

        buf
    }
}

struct Vpnv4Reach {
    pub update: Vec<Vpnv4Nlri>,
    pub nexthop: Option<Vpnv4Nexthop>,
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
        buf.put_u8(12); // Nexthop len
        // Nexthop RD.
        let rd = [0u8; 8];
        buf.put(&rd[..]);
        let nexthop: Ipv4Addr = if let Some(v) = &self.nexthop {
            v.nhop
        } else {
            Ipv4Addr::UNSPECIFIED
        };
        buf.put(&nexthop.octets()[..]);
        // SNPA
        buf.put_u8(0);
        // Prefix.
        for update in self.update.iter() {
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

struct Vpnv4Unreach {
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
            buf.put_u8(ip.prefix.prefix_len());
            let plen = nlri_psize(ip.prefix.prefix_len());
            buf.put(&ip.prefix.addr().octets()[0..plen]);
        }
        let withdraw_len: u16 = (buf.len() - withdraw_len_pos - 2) as u16;
        buf[withdraw_pos].copy_from_slice(&withdraw_len.to_be_bytes());

        // Attributes.
        let attr_len_pos = buf.len();
        buf.put_u16(0u16); // Placeholder
        let attr_pos: std::ops::Range<usize> = attr_len_pos..attr_len_pos + 2;

        for attr in update.attrs.iter() {
            attr.emit(&mut buf);
        }
        if update.vpnv4_update.len() > 0 {
            let vpnv4 = Vpnv4Reach {
                update: update.vpnv4_update,
                nexthop: update.vpnv4_nexthop,
            };
            vpnv4.attr_emit(&mut buf);
        }
        if update.vpnv4_withdraw.len() > 0 {
            let vpnv4 = Vpnv4Unreach {
                withdraw: update.vpnv4_withdraw,
            };
            vpnv4.attr_emit(&mut buf);
        }

        let attr_len: u16 = (buf.len() - attr_len_pos - 2) as u16;
        buf[attr_pos].copy_from_slice(&attr_len.to_be_bytes());

        // IPv4 unicast update.
        for ip in update.ipv4_update.iter() {
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

impl From<NotificationPacket> for BytesMut {
    fn from(notification: NotificationPacket) -> Self {
        let mut buf = BytesMut::new();
        let header: BytesMut = notification.header.into();
        buf.put(&header[..]);
        buf.put_u8(notification.code.into());
        buf.put_u8(notification.sub_code);
        buf.put(&notification.data[..]);

        const LENGTH_POS: std::ops::Range<usize> = 16..18;
        let length: u16 = buf.len() as u16;
        buf[LENGTH_POS].copy_from_slice(&length.to_be_bytes());

        buf
    }
}
