use bytes::{BufMut, BytesMut};

use crate::nlri_psize;

use super::{BgpHeader, NotificationPacket, OpenPacket, UpdatePacket};
use crate::Attr;

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

impl From<UpdatePacket> for BytesMut {
    fn from(update: UpdatePacket) -> Self {
        let mut buf = BytesMut::new();
        let header: BytesMut = update.header.into();
        buf.put(&header[..]);

        // Withdraw.
        if update.ipv4_withdraw.is_empty() {
            buf.put_u16(0u16);
        } else {
            return buf;
        }

        // Attributes.
        let attr_len_pos = buf.len();
        buf.put_u16(0u16); // Placeholder
        let attr_pos: std::ops::Range<usize> = attr_len_pos..attr_len_pos + 2;

        for attr in update.attrs.iter() {
            match attr {
                Attr::Origin(_v) => {
                    attr.emit(&mut buf);
                    // v.encode(&mut buf);
                }
                Attr::As2Path(_) => {
                    // TODO: Implement As2Path encoding
                }
                Attr::As4Path(attr) => {
                    attr.encode(&mut buf);
                }
                Attr::NextHop(attr) => {
                    attr.encode(&mut buf);
                }
                Attr::Med(attr) => {
                    attr.encode(&mut buf);
                }
                Attr::LocalPref(attr) => {
                    attr.encode(&mut buf);
                }
                Attr::AtomicAggregate(attr) => {
                    attr.encode(&mut buf);
                }
                Attr::Aggregator2(attr) => {
                    attr.encode(&mut buf);
                }
                Attr::Aggregator4(attr) => {
                    attr.encode(&mut buf);
                }
                Attr::OriginatorId(attr) => {
                    attr.encode(&mut buf);
                }
                Attr::ClusterList(attr) => {
                    attr.encode(&mut buf);
                }
                Attr::Community(attr) => {
                    attr.encode(&mut buf);
                }
                Attr::ExtendedCom(attr) => {
                    attr.encode(&mut buf);
                }
                Attr::Aigp(attr) => {
                    attr.encode(&mut buf);
                }
                Attr::LargeCom(attr) => {
                    attr.encode(&mut buf);
                }
                Attr::MpReachNlri(_) => {
                    // TODO: Implement MpReachNlri encoding
                }
                Attr::MpUnreachNlri(_) => {
                    // TODO: Implement MpUnreachNlri encoding
                }
            }
        }
        let attr_len: u16 = (buf.len() - attr_len_pos - 2) as u16;
        buf[attr_pos].copy_from_slice(&attr_len.to_be_bytes());

        // NLRI.
        for ip in update.ipv4_update.iter() {
            buf.put_u8(ip.prefix_len());
            let plen = nlri_psize(ip.prefix_len());
            buf.put(&ip.addr().octets()[0..plen]);
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
