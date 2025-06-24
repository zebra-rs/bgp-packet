use bgp_packet::*;
use hex_literal::hex;

fn parse(buf: &[u8]) {
    // Parse with AS4 = truue.
    let packet = parse_bgp_packet(buf, true);
    match packet {
        Ok(_) => {
            println!("parse success");
        }
        Err(err) => {
            println!("parse error {}", err);
        }
    }
}

#[test]
pub fn parse_evpn_test_1() {
    const PACKET: &[u8] = &hex!(
        "
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
00 41 02 00 00 00 2a 90 0f 00 26 00 19 46 02 21
00 01 01 02 03 04 00 02 00 00 00 00 00 00 00 00
00 00 00 00 00 00 30 5e e9 1e 08 4d 68 00 00 00
00
"
    );
    parse(PACKET);
}
