use std::fmt;
use std::str::FromStr;

use bytes::{BufMut, BytesMut};
use nom::{number::complete::be_u8, IResult};
use nom_derive::*;

use super::{CapabilityCode, Emit};
use crate::{Afi, Safi};

#[derive(Debug, PartialEq, NomBE, Clone, Ord, PartialOrd, Eq)]
pub struct AddPathValue {
    pub afi: Afi,
    pub safi: Safi,
    pub send_receive: AddPathSendReceive,
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy, Ord, PartialOrd, Eq)]
pub enum AddPathSendReceive {
    Receive = 1,
    Send = 2,
    SendReceive = 3,
    Unknown(u8),
}

impl From<AddPathSendReceive> for u8 {
    fn from(typ: AddPathSendReceive) -> Self {
        use AddPathSendReceive::*;
        match typ {
            Receive => 1,
            Send => 2,
            SendReceive => 3,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for AddPathSendReceive {
    fn from(typ: u8) -> Self {
        use AddPathSendReceive::*;
        match typ {
            1 => Receive,
            2 => Send,
            3 => SendReceive,
            v => Unknown(v),
        }
    }
}

impl AddPathSendReceive {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, val) = be_u8(input)?;
        let send_receive: Self = val.into();
        Ok((input, send_receive))
    }

    pub fn is_receive(&self) -> bool {
        *self == AddPathSendReceive::Receive || *self == AddPathSendReceive::SendReceive
    }

    pub fn is_send(&self) -> bool {
        *self == AddPathSendReceive::Send || *self == AddPathSendReceive::SendReceive
    }
}

impl fmt::Display for AddPathSendReceive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Receive => "Receive",
            Self::Send => "Send",
            Self::SendReceive => "SendReceive",
            Self::Unknown(_) => "Unknown",
        })
    }
}

impl FromStr for AddPathSendReceive {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "send" => Ok(AddPathSendReceive::Send),
            "receive" => Ok(AddPathSendReceive::Receive),
            "send-receive" => Ok(AddPathSendReceive::SendReceive),
            _ => Err(format!("Invalid AddPathSendReceive value: {}", s)),
        }
    }
}

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapabilityAddPath {
    pub values: Vec<AddPathValue>,
}

impl CapabilityAddPath {
    pub fn new(afi: Afi, safi: Safi, send_receive: u8) -> Self {
        Self {
            values: vec![AddPathValue {
                afi,
                safi,
                send_receive: send_receive.into(),
            }],
        }
    }
}

impl Emit for CapabilityAddPath {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::AddPath
    }

    fn len(&self) -> u8 {
        (self.values.len() * 4) as u8
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        for val in self.values.iter() {
            buf.put_u16(val.afi.into());
            buf.put_u8(val.safi.into());
            buf.put_u8(val.send_receive.into());
        }
    }
}

impl fmt::Display for CapabilityAddPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = write!(f, "AddPath: ");
        for (i, value) in self.values.iter().enumerate() {
            if i > 0 {
                let _ = write!(f, ", ");
            }
            let _ = write!(f, "{}/{}: {}", value.afi, value.safi, value.send_receive);
        }
        Ok(())
    }
}
