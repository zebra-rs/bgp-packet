use nom::IResult;

pub trait ParseBe<T> {
    fn parse_be(input: &[u8]) -> IResult<&[u8], T>;
}

pub trait ParseNlri<T> {
    fn parse_nlri(input: &[u8], addpath: bool) -> IResult<&[u8], T>;
}
