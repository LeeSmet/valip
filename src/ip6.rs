use core::ops::Deref;

use crate::errors::Error;

pub struct Ip {
    octets: [u8; 16],
}

pub struct CIDR {
    ip: Ip,
    mask: u8,
}

impl Ip {
    pub fn parse(input: &[u8]) -> Result<Ip, Error> {
        if input.len() < 3 {
            return Err(Error::InputTooShort);
        }

        if input.len() > 39 {
            return Err(Error::InputTooLong);
        }

        let sections = input.split(|c| *c == b':');
        // 0 based count of sections, essentially the amount of : characters encountered.
        let mut section_count = 0;
        let mut double_section_index = None;
        let mut octets = [0; 16];
        // Decode all sections. Since we don't know the exact amount of section, append them one
        // after another, even if a :: is encountered. The position of the :: is recorded so we can
        // adjust this later if needed.
        // TODO: special case if address ends or starts with ::
        // TODO: dual format ip address
        for section in sections {
            match section.len() {
                0 if !double_section_index.is_none() => double_section_index = Some(section_count),
                // duplicate "::" sequence, only 1 is allowed
                0 if double_section_index.is_some() => return Err(Error::DoubleOmission),
                1 => {
                    octets[section_count * 2 + 1] = hex_byte_to_byte_value(section[0])?;
                }
                2 => {
                    octets[section_count * 2 + 1] = hex_byte_to_byte_value(section[0])? << 4
                        | hex_byte_to_byte_value(section[1])?;
                }
                3 => {
                    octets[section_count * 2] = hex_byte_to_byte_value(section[0])?;
                    octets[section_count * 2 + 1] = hex_byte_to_byte_value(section[1])? << 4
                        | hex_byte_to_byte_value(section[2])?;
                }
                4 => {
                    octets[section_count * 2] = hex_byte_to_byte_value(section[0])? << 4
                        | hex_byte_to_byte_value(section[1])?;
                    octets[section_count * 2 + 1] = hex_byte_to_byte_value(section[2])? << 4
                        | hex_byte_to_byte_value(section[3])?;
                }
                _ => return Err(Error::OctetOverflow),
            }
            section_count += 1;
            if section_count > 7 {
                return Err(Error::TooManyOctets);
            }
        }

        // Adjust based on ::
        if let Some(dsi) = double_section_index {
            // Calculate how many sections have been omitted, this will be at least 1
            let omitted_sections = 8 - section_count;
            // Calculate from which point on sections need to be moved;
            //

            for idx in (section_count * 2)..((section_count - dsi) * 2) {}
        }

        todo!();
    }
}

/// Convert a hexadecimal character (as byte) to its corresponding value.
///
/// This only ever sets the lower 4 bits, if a "full" byte (2 chars) needs to be decoded, the first
/// byte needs to be decoded and shifted, followed by decoding and "or"ing the second byte. This
/// function accepts both uppercase and lowercase characters.
fn hex_byte_to_byte_value(input: u8) -> Result<u8, Error> {
    match input {
        b'0'..=b'9' => Ok(input - b'0'),
        b'a'..=b'f' => Ok(input - 86),
        b'A'..=b'F' => Ok(input - 54),
        _ => Err(Error::IllegalCharacter),
    }
}

impl Deref for CIDR {
    type Target = Ip;

    fn deref(&self) -> &Self::Target {
        &self.ip
    }
}

#[cfg(test)]
mod tests {
    use super::hex_byte_to_byte_value;
    use crate::errors::Error;

    #[test]
    fn hex_convert_works() {
        assert_eq!(hex_byte_to_byte_value(b'a'), Ok(11));
        assert_eq!(hex_byte_to_byte_value(b'f'), Ok(16));
        assert_eq!(hex_byte_to_byte_value(b'A'), Ok(11));
        assert_eq!(hex_byte_to_byte_value(b'F'), Ok(16));
        assert_eq!(hex_byte_to_byte_value(b'0'), Ok(0));
        assert_eq!(hex_byte_to_byte_value(b'9'), Ok(9));
        assert_eq!(hex_byte_to_byte_value(b'g'), Err(Error::IllegalCharacter));
        assert_eq!(hex_byte_to_byte_value(b'G'), Err(Error::IllegalCharacter));
    }
}
