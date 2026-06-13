/// Ghidra PackedFormat binary reader for .sla files.
/// Based on marshal.hh PackedDecode protocol.

#[derive(Debug, thiserror::Error)]
pub enum PackedError {
    #[error("unexpected end of data")]
    UnexpectedEof,
    #[error("invalid element marker at offset {0}")]
    InvalidMarker(usize),
    #[error("invalid attribute type {0}")]
    InvalidAttributeType(u8),
    #[error("decompression error: {0}")]
    DecompressError(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElementEvent {
    Start(u32),
    End(u32),
}

#[derive(Debug, Clone)]
pub enum AttributeValue {
    Bool(bool),
    SignedInt(i64),
    UnsignedInt(u64),
    String(String),
    SpaceIndex(u32),
    SpecialSpace(u32),
}

pub struct PackedReader {
    data: Vec<u8>,
    pos: usize,
}

impl PackedReader {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data, pos: 0 }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    fn read_byte(&mut self) -> Result<u8, PackedError> {
        if self.pos >= self.data.len() {
            return Err(PackedError::UnexpectedEof);
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn peek_byte(&self) -> Result<u8, PackedError> {
        if self.pos >= self.data.len() {
            return Err(PackedError::UnexpectedEof);
        }
        Ok(self.data[self.pos])
    }

    fn read_id(&mut self, first_byte: u8) -> Result<u32, PackedError> {
        let extend = (first_byte >> 5) & 1;
        let mut id = (first_byte & 0x1F) as u32;
        if extend == 1 {
            let next = self.read_byte()?;
            id |= ((next & 0x7F) as u32) << 5;
        }
        Ok(id)
    }

    pub fn read_packed_int(&mut self) -> Result<u64, PackedError> {
        let mut result: u64 = 0;
        let mut shift = 0;
        loop {
            let b = self.read_byte()?;
            result |= ((b & 0x7F) as u64) << shift;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift > 63 {
                break;
            }
        }
        Ok(result)
    }

    pub fn read_packed_signed(&mut self) -> Result<i64, PackedError> {
        let val = self.read_packed_int()?;
        Ok(val as i64)
    }

    pub fn read_string_of_length(&mut self, len: usize) -> Result<String, PackedError> {
        if self.pos + len > self.data.len() {
            return Err(PackedError::UnexpectedEof);
        }
        let s = String::from_utf8_lossy(&self.data[self.pos..self.pos + len]).to_string();
        self.pos += len;
        Ok(s)
    }

    pub fn next_event(&mut self) -> Result<Option<ElementEvent>, PackedError> {
        if self.is_empty() {
            return Ok(None);
        }
        let b = self.peek_byte()?;
        let marker = b >> 6;
        match marker {
            0 => Ok(None),
            1 => {
                self.read_byte()?;
                let id = self.read_id(b)?;
                Ok(Some(ElementEvent::Start(id)))
            }
            2 => {
                self.read_byte()?;
                let id = self.read_id(b)?;
                Ok(Some(ElementEvent::End(id)))
            }
            _ => Ok(None),
        }
    }

    pub fn read_attribute(&mut self) -> Result<Option<(u32, AttributeValue)>, PackedError> {
        if self.is_empty() {
            return Ok(None);
        }
        let b = self.peek_byte()?;
        let marker = b >> 6;
        if marker != 3 {
            return Ok(None);
        }
        self.read_byte()?;
        let attr_id = self.read_id(b)?;
        let type_byte = self.read_byte()?;
        let type_code = type_byte >> 4;
        let length_code = (type_byte & 0x0F) as usize;

        let value = match type_code {
            1 => AttributeValue::Bool(length_code != 0),
            2 => {
                let v = self.read_packed_int()?;
                AttributeValue::SignedInt(v as i64)
            }
            3 => {
                let v = self.read_packed_int()?;
                AttributeValue::SignedInt(-(v as i64))
            }
            4 => {
                let v = self.read_packed_int()?;
                AttributeValue::UnsignedInt(v)
            }
            5 => {
                let v = self.read_packed_int()?;
                AttributeValue::SpaceIndex(v as u32)
            }
            6 => {
                AttributeValue::SpecialSpace(length_code as u32)
            }
            7 => {
                let len = if length_code == 0x0F {
                    self.read_packed_int()? as usize
                } else {
                    length_code
                };
                let s = self.read_string_of_length(len)?;
                AttributeValue::String(s)
            }
            _ => return Err(PackedError::InvalidAttributeType(type_code)),
        };

        Ok(Some((attr_id, value)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_packed_int_single_byte() {
        let mut reader = PackedReader::new(vec![42]);
        assert_eq!(reader.read_packed_int().unwrap(), 42);
    }

    #[test]
    fn read_packed_int_multi_byte() {
        let mut reader = PackedReader::new(vec![0x80 | 0x01, 0x01]);
        assert_eq!(reader.read_packed_int().unwrap(), 129);
    }

    #[test]
    fn reader_empty() {
        let reader = PackedReader::new(vec![]);
        assert!(reader.is_empty());
        assert_eq!(reader.remaining(), 0);
    }

    #[test]
    fn read_string() {
        let mut reader = PackedReader::new(b"hello".to_vec());
        assert_eq!(reader.read_string_of_length(5).unwrap(), "hello");
    }
}
