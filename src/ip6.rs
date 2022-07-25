use core::ops::Deref;

use crate::errors::Error;

#[derive(Debug, PartialEq, Eq)]
pub struct Ip {
    octets: [u8; 16],
}

#[derive(Debug, PartialEq, Eq)]
pub struct CIDR {
    ip: Ip,
    mask: u8,
}

impl Ip {
    pub const fn new(octets: [u8; 16]) -> Ip {
        Ip { octets }
    }

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
        // Remember if the previous section was empty or not. This is unfortunately needed for
        // addresses with leading or ending ::.
        let mut last_seen_empty = false;
        // Decode all sections. Since we don't know the exact amount of section, append them one
        // after another, even if a :: is encountered. The position of the :: is recorded so we can
        // adjust this later if needed.
        // TODO: special case if address ends or starts with ::
        // TODO: dual format ip address
        for section in sections {
            // Special handling to catch leading single :
            if section_count == 1 && double_section_index.is_some() && !section.is_empty() {
                return Err(Error::MissingOctet);
            }
            match section.len() {
                0 => {
                    if double_section_index.is_none() {
                        double_section_index = Some(section_count);
                    } else if double_section_index.is_some() && section_count != 1 {
                        // Double ::, this is not accpeted
                        return Err(Error::DoubleOmission);
                    }
                    // The other case indicates a leading ::, this is fine
                }
                // 0 if double_section_index.is_none() => double_section_index = Some(section_count),
                // // duplicate "::" sequence, only 1 is allowed
                // 0 if double_section_index.is_some() => return Err(Error::DoubleOmission),
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
            last_seen_empty = section.is_empty();
        }

        // trailing single : character
        if last_seen_empty {
            return Err(Error::MissingOctet);
        }

        // Adjust based on ::
        if let Some(dsi) = double_section_index {
            // Calculate how many sections have been omitted, this will be at least 1
            let omitted_sections = 8 - section_count;
            // Calculate from which point on sections need to be moved;
            let start = (dsi + 1 + omitted_sections) * 2;
            // TODO: const
            let end = 16;
            // Move sections, iterate backward so we don't overwrite any data we later still need
            // to move if the omitted part is short.
            for idx in (start..end).rev() {
                octets[idx] = octets[idx - omitted_sections * 2];
            }
            // Zero out omitted sections
            for idx in (dsi * 2)..((dsi + omitted_sections) * 2) {
                octets[idx] = 0;
            }
        }

        Ok(Ip { octets })
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
    use super::{hex_byte_to_byte_value, Ip};
    use crate::errors::Error;

    #[test]
    fn hex_convert() {
        assert_eq!(hex_byte_to_byte_value(b'a'), Ok(11));
        assert_eq!(hex_byte_to_byte_value(b'f'), Ok(16));
        assert_eq!(hex_byte_to_byte_value(b'A'), Ok(11));
        assert_eq!(hex_byte_to_byte_value(b'F'), Ok(16));
        assert_eq!(hex_byte_to_byte_value(b'0'), Ok(0));
        assert_eq!(hex_byte_to_byte_value(b'9'), Ok(9));
        assert_eq!(hex_byte_to_byte_value(b'g'), Err(Error::IllegalCharacter));
        assert_eq!(hex_byte_to_byte_value(b'G'), Err(Error::IllegalCharacter));
    }

    #[test]
    fn parse_ip6() {
        assert_eq!(
            Ip::parse("2010::1".as_bytes()),
            Ok(Ip::new([32, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]))
        );
        assert_eq!(
            Ip::parse("::1".as_bytes()),
            Ok(Ip::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]))
        );
        assert_eq!(
            Ip::parse("::1001:1".as_bytes()),
            Ok(Ip::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 1, 0, 1]))
        );
        assert_eq!(
            Ip::parse("2c01::".as_bytes()),
            Ok(Ip::new([44, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))
        );
        assert_eq!(
            Ip::parse("2c01:af::".as_bytes()),
            Ok(Ip::new([44, 1, 0, 175, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))
        );
    }
}
