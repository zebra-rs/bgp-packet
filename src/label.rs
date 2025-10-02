pub struct Label {
    value: u32,
    bos: bool,
}

impl From<&[u8]> for Label {
    fn from(val: &[u8]) -> Self {
        Label {
            value: 0,
            bos: false,
        }
    }
}
