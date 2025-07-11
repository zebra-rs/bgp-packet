use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom::multi::count;
use nom::number::complete::{be_u16, be_u32};
use nom_derive::*;
use std::collections::VecDeque;
use std::fmt;
use std::str::FromStr;

use crate::{AttrType, ParseBe, many0};

use super::aspath_token::{Token, tokenizer};
use super::{AttrEmitter, AttrFlags};

pub const AS_SET: u8 = 1;
pub const AS_SEQ: u8 = 2;
pub const AS_CONFED_SEQ: u8 = 3;
pub const AS_CONFED_SET: u8 = 4;

#[allow(dead_code)]
pub const AS_TRANS: u16 = 23456;

#[derive(Debug, NomBE)]
pub struct AsSegmentHeader {
    pub typ: u8,
    pub length: u8,
}

#[derive(Clone, Debug)]
pub struct As2Segment {
    pub typ: u8,
    pub asn: Vec<u16>,
}

#[derive(Clone, Debug)]
pub struct As2Path {
    pub segs: Vec<As2Segment>,
}

impl ParseBe<As2Path> for As2Path {
    fn parse_be(input: &[u8]) -> IResult<&[u8], As2Path> {
        let (input, segs) = many0(parse_bgp_attr_as2_segment).parse(input)?;
        Ok((input, As2Path { segs }))
    }
}

fn parse_bgp_attr_as2_segment(input: &[u8]) -> IResult<&[u8], As2Segment> {
    let (input, header) = AsSegmentHeader::parse_be(input)?;
    let (input, asns) = count(be_u16, header.length as usize).parse(input)?;
    let segment = As2Segment {
        typ: header.typ,
        asn: asns.into_iter().collect(),
    };
    Ok((input, segment))
}

fn parse_bgp_attr_as4_segment(input: &[u8]) -> IResult<&[u8], As4Segment> {
    let (input, header) = AsSegmentHeader::parse_be(input)?;
    let (input, asns) = count(be_u32, header.length as usize).parse(input)?;
    let segment = As4Segment {
        typ: header.typ,
        asn: asns.into_iter().collect(),
    };
    Ok((input, segment))
}

#[derive(Clone, Debug)]
pub struct As4Segment {
    pub typ: u8,
    pub asn: Vec<u32>,
}

impl As4Segment {
    pub fn new(typ: u8) -> Self {
        Self {
            typ,
            asn: Vec::new(),
        }
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.typ);
        buf.put_u8(self.asn.len() as u8);
        self.asn.iter().for_each(|x| buf.put_u32(*x));
    }
}

pub fn asn_to_string(val: u32) -> String {
    if val > 65535 {
        let hval: u32 = (val & 0xFFFF0000) >> 16;
        let lval: u32 = val & 0x0000FFFF;
        hval.to_string() + "." + &lval.to_string()
    } else {
        val.to_string()
    }
}

impl fmt::Display for As4Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v = self
            .asn
            .iter()
            .map(|x| asn_to_string(*x))
            .collect::<Vec<String>>()
            .join(" ");
        match self.typ {
            AS_SET => write!(f, "{{{v}}}"),
            AS_CONFED_SEQ => write!(f, "({v})"),
            AS_CONFED_SET => write!(f, "[{v}]"),
            AS_SEQ => write!(f, "{v}"),
            _ => write!(f, "{v}"),
        }
    }
}

#[derive(Clone)]
pub struct As4Path {
    pub segs: VecDeque<As4Segment>,
}

impl AttrEmitter for As4Path {
    fn attr_flags(&self) -> AttrFlags {
        AttrFlags::new().with_transitive(true)
    }

    fn attr_type(&self) -> AttrType {
        AttrType::AsPath
    }

    fn len(&self) -> Option<usize> {
        None
    }

    fn emit(&self, buf: &mut BytesMut) {
        self.segs.iter().for_each(|x| x.emit(buf));
    }
}

impl ParseBe<As4Path> for As4Path {
    fn parse_be(input: &[u8]) -> IResult<&[u8], As4Path> {
        let (input, segs) = many0(parse_bgp_attr_as4_segment).parse(input)?;
        Ok((input, As4Path { segs: segs.into() }))
    }
}

impl fmt::Display for As4Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v = self
            .segs
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>()
            .join(" ");
        write!(f, "{v}")
    }
}

impl fmt::Debug for As4Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, " AS Path: {}", self)
    }
}

macro_rules! segment_reset {
    ($typ:expr, $before:expr, $after:expr, $seg:expr, $aspath:expr) => {
        if $typ != $before {
            return Err(());
        }
        $typ = $after;
        if !$seg.asn.is_empty() {
            $aspath.segs.push_back($seg);
            $seg = As4Segment::new($typ);
        } else {
            $seg.typ = $typ;
        }
    };
}

impl FromStr for As4Path {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut aspath = As4Path::new();
        let tokens = tokenizer(String::from(s)).unwrap();
        let mut segment_type = AS_SEQ;
        let mut segment = As4Segment::new(segment_type);

        for token in tokens.iter() {
            match token {
                Token::As(asn) => {
                    segment.asn.push(*asn);
                }
                Token::AsSetStart => {
                    segment_reset!(segment_type, AS_SEQ, AS_SET, segment, aspath);
                }
                Token::AsSetEnd => {
                    segment_reset!(segment_type, AS_SET, AS_SEQ, segment, aspath);
                }
                Token::AsConfedSeqStart => {
                    segment_reset!(segment_type, AS_SEQ, AS_CONFED_SEQ, segment, aspath);
                }
                Token::AsConfedSeqEnd => {
                    segment_reset!(segment_type, AS_CONFED_SEQ, AS_SEQ, segment, aspath);
                }
                Token::AsConfedSetStart => {
                    segment_reset!(segment_type, AS_SEQ, AS_CONFED_SET, segment, aspath);
                }
                Token::AsConfedSetEnd => {
                    segment_reset!(segment_type, AS_CONFED_SET, AS_SEQ, segment, aspath);
                }
            }
        }

        if !segment.asn.is_empty() {
            aspath.segs.push_back(segment);
        }

        Ok(aspath)
    }
}

impl As4Path {
    pub fn new() -> Self {
        Self {
            segs: VecDeque::new(),
        }
    }

    pub fn prepend(&self, other: Self) -> Self {
        let mut aspath = self.clone();
        if !aspath.segs.is_empty() && aspath.segs[0].typ == AS_SEQ {
            let mut asn = aspath.segs[0].asn.clone();
            aspath.segs[0].asn = other.segs[0].asn.clone();
            aspath.segs[0].asn.append(&mut asn);
        } else {
            aspath.segs.push_front(other.segs[0].clone());
        }
        aspath
    }
}

impl Default for As4Path {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        let aspath: As4Path = As4Path::from_str("1 2 3 65536").unwrap();
        assert_eq!(aspath.to_string(), "1 2 3 1.0");

        let aspath: As4Path = As4Path::from_str("1 2 3 {4} 4294967295").unwrap();
        assert_eq!(aspath.to_string(), "1 2 3 {4} 65535.65535");

        let aspath: As4Path = As4Path::from_str("1 2 3 [4 5] 6").unwrap();
        assert_eq!(aspath.to_string(), "1 2 3 [4 5] 6");

        let aspath: As4Path = As4Path::from_str("1 2 3 [4 5] 6 (7)").unwrap();
        assert_eq!(aspath.to_string(), "1 2 3 [4 5] 6 (7)");
    }

    #[test]
    fn prepend() {
        let aspath: As4Path = As4Path::from_str("10 11 12").unwrap();
        let prepend: As4Path = As4Path::from_str("1 2 3").unwrap();
        let result = aspath.prepend(prepend);
        assert_eq!(result.to_string(), "1 2 3 10 11 12")
    }
}
