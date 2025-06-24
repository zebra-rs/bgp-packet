use std::fmt;
use std::net::Ipv4Addr;

use nom::IResult;
use nom::error::{ErrorKind, make_error};
use nom_derive::*;

use super::cap::{CapabilityHeader, CapabilityPacket};
use super::{BgpHeader, many0};

pub const BGP_VERSION: u8 = 4;

#[derive(PartialEq, NomBE)]
pub struct OpenPacket {
    pub header: BgpHeader,
    pub version: u8,
    pub asn: u16,
    pub hold_time: u16,
    pub bgp_id: [u8; 4],
    pub opt_param_len: u8,
    #[nom(Ignore)]
    pub caps: Vec<CapabilityPacket>,
}

#[derive(Debug, PartialEq, NomBE)]
pub struct OpenExtended {
    pub non_ext_op_type: u8,
    pub ext_opt_parm_len: u16,
}

impl OpenPacket {
    pub fn new(
        header: BgpHeader,
        asn: u16,
        hold_time: u16,
        router_id: &Ipv4Addr,
        caps: Vec<CapabilityPacket>,
    ) -> OpenPacket {
        OpenPacket {
            header,
            version: BGP_VERSION,
            asn,
            hold_time,
            bgp_id: router_id.octets(),
            opt_param_len: 0,
            caps,
        }
    }

    pub fn parse_packet(input: &[u8]) -> IResult<&[u8], OpenPacket> {
        let (input, mut packet) = OpenPacket::parse_be(input)?;
        let (input, len) = if packet.opt_param_len == 255 {
            let (input, ext) = OpenExtended::parse_be(input)?;
            if ext.non_ext_op_type != 255 {
                return Err(nom::Err::Error(make_error(input, ErrorKind::Tag)));
            }
            (input, ext.ext_opt_parm_len)
        } else {
            (input, packet.opt_param_len as u16)
        };
        if input.len() != len as usize {
            return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
        }
        let (opts, input) = input.split_at(len as usize);
        let (_, caps) = many0(parse_caps).parse(opts)?;
        for mut cap in caps.into_iter() {
            packet.caps.append(&mut cap);
        }
        Ok((input, packet))
    }
}

fn parse_caps(input: &[u8]) -> IResult<&[u8], Vec<CapabilityPacket>> {
    let (input, header) = CapabilityHeader::parse_be(input)?;
    let (opts, input) = input.split_at(header.length as usize);
    let (_, caps) = many0(CapabilityPacket::parse_cap).parse(opts)?;
    Ok((input, caps))
}

impl fmt::Debug for OpenPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Open Message:")?;
        write!(f, "\n Capability")?;
        for cap in self.caps.iter() {
            write!(f, "\n  {:?}", cap)?;
        }
        Ok(())
    }
}
