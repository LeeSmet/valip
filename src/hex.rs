use crate::errors::Error;

/// Convert a hexadecimal character (as byte) to its corresponding value.
///
/// This only ever sets the lower 4 bits, if a "full" byte (2 chars) needs to be decoded, the first
/// byte needs to be decoded and shifted, followed by decoding and "or"ing the second byte. This
/// function accepts both uppercase and lowercase characters.
pub fn hex_byte_to_byte_value(input: u8) -> Result<u8, Error> {
    match input {
        b'0'..=b'9' => Ok(input - b'0'),
        b'a'..=b'f' => Ok(input - 87),
        b'A'..=b'F' => Ok(input - 55),
        _ => Err(Error::IllegalCharacter),
    }
}

#[cfg(test)]
mod tests {
    use super::hex_byte_to_byte_value;
    use crate::errors::Error;

    #[test]
    fn hex_convert() {
        assert_eq!(hex_byte_to_byte_value(b'a'), Ok(10));
        assert_eq!(hex_byte_to_byte_value(b'f'), Ok(15));
        assert_eq!(hex_byte_to_byte_value(b'A'), Ok(10));
        assert_eq!(hex_byte_to_byte_value(b'F'), Ok(15));
        assert_eq!(hex_byte_to_byte_value(b'0'), Ok(0));
        assert_eq!(hex_byte_to_byte_value(b'9'), Ok(9));
        assert_eq!(hex_byte_to_byte_value(b'c'), Ok(12));
        assert_eq!(hex_byte_to_byte_value(b'g'), Err(Error::IllegalCharacter));
        assert_eq!(hex_byte_to_byte_value(b'G'), Err(Error::IllegalCharacter));
    }
}
