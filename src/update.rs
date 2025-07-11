use std::fmt;

use crate::Attr;

use super::{BGP_HEADER_LEN, BgpHeader, BgpType};
use ipnet::Ipv4Net;
use nom_derive::*;

#[derive(NomBE)]
pub struct UpdatePacket {
    pub header: BgpHeader,
    #[nom(Ignore)]
    pub attrs: Vec<Attr>,
    #[nom(Ignore)]
    pub ipv4_update: Vec<Ipv4Net>,
    #[nom(Ignore)]
    pub ipv4_withdraw: Vec<Ipv4Net>,
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
            attrs: Vec::new(),
            ipv4_update: Vec::new(),
            ipv4_withdraw: Vec::new(),
        }
    }
}

impl fmt::Debug for UpdatePacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Update Message:")?;
        for attr in self.attrs.iter() {
            write!(f, "\n{:?}", attr)?;
        }
        Ok(())
    }
}

impl fmt::Display for UpdatePacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Update")?;
        for attr in self.attrs.iter() {
            writeln!(f, "{}", attr)?;
        }
        Ok(())
    }
}
