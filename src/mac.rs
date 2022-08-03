use crate::errors::Error;
use crate::hex::hex_byte_to_byte_value;

const MAC_BYTE_SIZE: usize = 6;
const MAC_READABLE_SIZE: usize = 17;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mac {
    raw: [u8; MAC_BYTE_SIZE],
}

impl Mac {
    /// Create a new mac address from the given raw bytes.
    pub const fn new(raw: [u8; MAC_BYTE_SIZE]) -> Mac {
        Mac { raw }
    }

    /// Parse ASCII bytes to a mac address.
    pub fn parse(input: &[u8]) -> Result<Mac, Error> {
        if input.len() < MAC_READABLE_SIZE {
            return Err(Error::InputTooShort);
        }
        if input.len() > MAC_READABLE_SIZE {
            return Err(Error::InputTooLong);
        }

        let mut bytes = 0;
        let mut raw = [0; MAC_BYTE_SIZE];

        for byte in input.split(|&c| c == b':') {
            if byte.len() != 2 {
                // TODO
                return Err(Error::IllegalCharacter);
            }

            raw[bytes] = hex_byte_to_byte_value(byte[0])? << 4 | hex_byte_to_byte_value(byte[1])?;
            bytes += 1;
            if bytes > MAC_BYTE_SIZE {
                return Err(Error::TooManyOctets);
            }
        }

        if bytes != MAC_BYTE_SIZE {
            return Err(Error::InsufficientOctets);
        }

        Ok(Mac { raw })
    }
}
