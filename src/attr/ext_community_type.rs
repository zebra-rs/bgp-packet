#[repr(u8)]
pub enum ExtCommunityType {
    TransTwoOctetAS = 0x00,
    // TransIpv4Addr = 0x01,
    // TransFourOctetAS = 0x03,
    TransOpaque = 0x03,
}

#[repr(u8)]
pub enum ExtCommunitySubType {
    RouteTarget = 0x02,
    RouteOrigin = 0x03,
    Opaque = 0x0c,
}
