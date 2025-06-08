use bytes::{BufMut, BytesMut};

use crate::{AttrFlags, AttrType};

pub trait AttrEmitter {
    fn attr_flags(&self) -> AttrFlags;
    fn attr_type(&self) -> AttrType;
    fn len(&self) -> u16;
    fn emit(&self, buf: &mut BytesMut);

    fn attr_emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.attr_flags().into());
        buf.put_u8(self.attr_type().into());
        if self.attr_flags().extended() {
            buf.put_u16(self.len());
        } else {
            buf.put_u8(self.len() as u8);
        }
        self.emit(buf);
    }
}
