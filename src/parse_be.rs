use nom::IResult;

pub trait ParseBe<T> {
    fn parse_be(input: &[u8]) -> IResult<&[u8], T>;
}
