// This is only here because qpack is new and quinn no uses it yet.
// TODO remove allow dead code
#![allow(dead_code)]

use std::borrow::Cow;
use std::io::Cursor;
use bytes::Buf;

use super::parser::Parser;
use super::table::HeaderField;
use super::dyn_table::DynamicTable;
use super::static_table::StaticTable;


#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidIntegerPrimitive,
    InvalidStringPrimitive,
    BadBufferLen,
    BadMaximumDynamicTableSize,
    BadNameIndexOnDynamicTable,
    BadNameIndexOnStaticTable
}


pub struct Decoder {
    pub table: DynamicTable
}


impl Decoder {
    pub fn new() -> Decoder {
        Decoder { table: DynamicTable::new() }
    }

    pub fn get_static_field(&self, index: usize) -> Option<&HeaderField> {
        StaticTable::get(index)
    }

    pub fn get_rel_field(&self, rel_index: usize) -> Option<&HeaderField> {
        // TODO get true field (now assuming relative = absolute index)
        self.table.get(rel_index)
    }

    pub fn feed<T: Buf>(&mut self, buf: &mut T) -> Result<(), Error> {
        let block_len = Parser::new(buf).integer(8)
            .map_err(|_| Error::InvalidIntegerPrimitive)?;

        if block_len as usize != buf.remaining() {
            return Err(Error::BadBufferLen);
        }

        while buf.has_remaining() {
            match buf.get_u8() {
                x if x & 128u8 == 128u8
                    => self.read_name_insert_by_ref(x, buf)?,
                x if x & 64u8 == 64u8 => self.read_name_insert(x, buf)?,
                x if x & 32u8 == 32u8 => self.read_table_size_update(x, buf)?,
                x => self.read_duplicate_entry(x, buf)?
            }
        }

        Ok(())
    }

    fn read_name_insert_by_ref<T: Buf>(&mut self, byte: u8, buf: &mut T)
        -> Result<(), Error>
    {
        let is_static_table = byte & 64u8 == 64u8;

        let mut parser = Parser::new(buf);
        let name_index = parser.integer_from(6, byte)
            .map_err(|_| Error::InvalidIntegerPrimitive)? as usize;
        let value = parser.string(8)
            .map_err(|_| Error::InvalidStringPrimitive)?;

        let name = if is_static_table {
            StaticTable::get(name_index)
                .map(|x| x.name.clone())
                .ok_or(Error::BadNameIndexOnStaticTable)?
        } else {
            // TODO get true field (now assuming relative = absolute index)
            self.table.get(name_index)
                .map(|x| x.name.clone())
                .ok_or(Error::BadNameIndexOnDynamicTable)?
        };

        self.table.put_field(HeaderField {
            name: name.clone(),
            value: Cow::Owned(value)
        });

        Ok(())
    }

    fn read_name_insert<T: Buf>(&mut self, _byte: u8, _buf: &mut T)
        -> Result<(), Error>
    {
        unimplemented!("byte: {}", _byte);
    }

    fn read_table_size_update<T: Buf>(&mut self, byte: u8, buf: &mut T)
        -> Result<(), Error>
    {
        let size = Parser::new(buf).integer_from(5, byte)
            .map_err(|_| Error::InvalidIntegerPrimitive)?;

        self.table.set_max_mem_size(size as usize)
            .map_err(|_| Error::BadMaximumDynamicTableSize)
            .map(|_| ())
    }

    fn read_duplicate_entry<T: Buf>(&mut self, _byte: u8, _buf: &mut T)
        -> Result<(), Error>
    {
        unimplemented!();
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    /**
     * https://tools.ietf.org/html/draft-ietf-quic-qpack-00
     * 3.3.  QPACK Encoder Stream
     */
    #[test]
    fn test_wrong_block_length() {
        let mut decoder = Decoder::new();
        let bytes: [u8; 1] = [
            5 // block length
        ];

        let mut cursor = Cursor::new(&bytes);
        let res = decoder.feed(&mut cursor);

        assert_eq!(res, Err(Error::BadBufferLen));
    }

    /**
     * https://tools.ietf.org/html/draft-ietf-quic-qpack-00
     * 3.3.1.  Insert With Name Reference
     */
    #[test]
    fn test_insert_field_with_name_ref_into_dynamic_table() {
        let mut decoder = Decoder::new();

        let value = "some value";
        assert!(value.len() < 127); // just to make sure size fit in prefix

        let name_index = 1u8;
        assert!(name_index < 64); // just to make sure name index fit in prefix

        let use_static = true;
        let model_field = decoder.get_static_field(name_index as usize)
            .map(|x| x.clone());
        let expected_field = HeaderField::new(
            model_field.expect("name index exists").name,
            value);

        let mut bytes: Vec<u8> = Vec::new();
        // block length
        bytes.push(2u8 + value.bytes().len() as u8);
        // 0b1 message code, dynamic = 0 or static table = 1, name index
        bytes.push(128u8
                   | if use_static { 64u8 } else { 0u8 }
                   | name_index);
        // huffman = 1 or not = 0, value size
        bytes.push(value.len() as u8);
        // value
        bytes.extend(value.bytes());

        let mut cursor = Cursor::new(&bytes);
        let res = decoder.feed(&mut cursor);
        assert_eq!(res, Ok(()));

        let field = decoder.get_rel_field(0);
        assert_eq!(field, Some(&expected_field));
    }

    /**
     * https://tools.ietf.org/html/draft-ietf-quic-qpack-00
     * 3.3.4.  Dynamic Table Size Update
     */
    #[test]
    fn test_dynamic_table_size_update() {
        let mut decoder = Decoder::new();
        let bytes: [u8; 2] = [
            1, // block length
            32 | 25 // 0b001 message code, size
        ];
        let expected_size = 25;

        let mut cursor = Cursor::new(&bytes);
        let res = decoder.feed(&mut cursor);
        assert_eq!(res, Ok(()));

        let actual_max_size = decoder.table.max_mem_size();
        assert_eq!(actual_max_size, expected_size);
    }

}
