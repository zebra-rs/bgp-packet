use std::fmt;

use crate::{Attr, Ipv4Nlri};

use super::{BGP_HEADER_LEN, BgpHeader, BgpType};
use nom_derive::*;

#[derive(NomBE)]
pub struct UpdatePacket {
    pub header: BgpHeader,
    #[nom(Ignore)]
    pub attrs: Vec<Attr>,
    #[nom(Ignore)]
    pub ipv4_update: Vec<Ipv4Nlri>,
    #[nom(Ignore)]
    pub ipv4_withdraw: Vec<Ipv4Nlri>,
    #[nom(Ignore)]
    pub add_path: bool,
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
            add_path: false,
        }
    }
}

impl fmt::Debug for UpdatePacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Update Message:")?;
        for attr in self.attrs.iter() {
            write!(f, "\n {:?}", attr)?;
        }
        write!(f, "\n IPv4 Updates:")?;
        if self.ipv4_update.is_empty() {
            write!(f, " None")?;
        } else {
            for update in self.ipv4_update.iter() {
                write!(f, "\n  {}", update.prefix)?;
            }
        }
        write!(f, "\n IPv4 Withdraw:")?;
        if self.ipv4_withdraw.is_empty() {
            write!(f, " None")?;
        } else {
            for withdraw in self.ipv4_withdraw.iter() {
                write!(f, "\n  {}", withdraw.prefix)?;
            }
        }
        Ok(())
    }
}
