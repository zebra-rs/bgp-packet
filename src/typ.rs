use nom::number::complete::be_u8;
use nom::IResult;
use nom_derive::*;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum BgpType {
    Open,
    Update,
    Notification,
    Keepalive,
    RouteRefresh,
    Capability,
    Unknown(u8),
}

impl From<BgpType> for u8 {
    fn from(typ: BgpType) -> Self {
        use BgpType::*;
        match typ {
            Open => 1,
            Update => 2,
            Notification => 3,
            Keepalive => 4,
            RouteRefresh => 5,
            Capability => 6,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for BgpType {
    fn from(val: u8) -> Self {
        use BgpType::*;
        match val {
            1 => Open,
            2 => Update,
            3 => Notification,
            4 => Keepalive,
            5 => RouteRefresh,
            6 => Capability,
            v => Unknown(v),
        }
    }
}

impl BgpType {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, typ) = be_u8(input)?;
        let bgp_type: Self = typ.into();
        Ok((input, bgp_type))
    }
}
