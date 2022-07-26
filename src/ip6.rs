use core::ops::Deref;

use crate::errors::Error;

const IP_BYTES: usize = 16;

#[derive(Debug, PartialEq, Eq)]
pub struct Ip {
    octets: [u8; IP_BYTES],
}

#[derive(Debug, PartialEq, Eq)]
pub struct CIDR {
    ip: Ip,
    mask: u8,
}

impl Ip {
    pub const fn new(octets: [u8; IP_BYTES]) -> Ip {
        Ip { octets }
    }

    pub fn parse(input: &[u8]) -> Result<Ip, Error> {
        // :: is the shortest possible IPv6
        if input.len() < 2 {
            return Err(Error::InputTooShort);
        }

        if input.len() > 39 {
            return Err(Error::InputTooLong);
        }

        let sections = input.split(|&c| c == b':');
        // 0 based count of sections.
        let mut section_count = 0;
        let mut double_section_index = None;
        let mut octets = [0; IP_BYTES];
        // Remember if the previous section was empty or not. This is unfortunately needed for
        // addresses with leading or ending ::.
        let mut last_seen_empty = false;
        // Decode all sections. Since we don't know the exact amount of section, append them one
        // after another, even if a :: is encountered. The position of the :: is recorded so we can
        // adjust this later if needed.
        // TODO: dual format ip address
        for section in sections {
            // Required for trailing :: characters which only omit the last section
            if section_count == 8 && !section.is_empty() {
                return Err(Error::TooManyOctets);
            }

            // Special handling to catch leading single :
            if section_count == 0 && last_seen_empty && !section.is_empty() {
                return Err(Error::MissingOctet);
            }
            match section.len() {
                0 if section_count == 0 && !last_seen_empty => {
                    // Don't do anything, this ignores the additional section from a leading :, but
                    // mark that we did see an empty section so we don't keep swallowing :
                    // characters.
                    last_seen_empty = true;
                    continue;
                }
                0 if section_count > 0 || last_seen_empty => match double_section_index {
                    None => double_section_index = Some(section_count),
                    Some(dsi) if last_seen_empty => {
                        if section_count != dsi + 1 {
                            return Err(Error::DoubleOmission);
                        }
                    }
                    _ => return Err(Error::DoubleOmission),
                },
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
            if section_count > 8 {
                if let Some(dsi) = double_section_index {
                    // The following is only possible for a trailing ::
                    if !(dsi == section_count - 2 && section.is_empty()) {
                        return Err(Error::TooManyOctets);
                    }
                } else {
                    return Err(Error::TooManyOctets);
                }
            }
            last_seen_empty = section.is_empty();
        }

        // Check for trailing single : character
        if last_seen_empty {
            if let Some(dsi) = double_section_index {
                // add 2 to the index of the double section for the check (which verifies if the
                // last characters is a ::. Dsi points to the first :, then there is the implied
                // omitted section between the ::, followed by the omitted final section, therefore,
                // +2.
                if dsi + 2 != section_count {
                    return Err(Error::MissingOctet);
                } else {
                    // Decrement the section count so we have an unambiguous value for the shifting
                    // section.
                    section_count -= 1;
                }
            }
        }

        // Ensure we have sufficient input
        if section_count < 8 && !double_section_index.is_some() {
            return Err(Error::MissingOctet);
        }

        // Adjust based on ::
        if let Some(dsi) = double_section_index {
            // Calculate how many sections have been omitted, this will be at least 1
            // Notice that we subtract section count from 9: there are 8 sections, but we also
            // count 1 section for the omitted sections;
            let omitted_sections = 9 - section_count;
            // Calculate from which point on sections need to be moved;
            let start = (dsi + omitted_sections) * 2;
            // Move sections, iterate backward so we don't overwrite any data we later still need
            // to move if the omitted part is short.
            // In this loop we need to account for the fact that we wrote 2 0 bytes for the omitted
            // section, irrespectively of how long it it.
            for idx in (start..IP_BYTES).rev() {
                octets[idx] = octets[idx - (omitted_sections - 1) * 2];
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
        b'a'..=b'f' => Ok(input - 87),
        b'A'..=b'F' => Ok(input - 55),
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
        assert_eq!(
            Ip::parse("f0a:f0b::f0c:f0d:f0e".as_bytes()),
            Ok(Ip::new([
                15, 10, 15, 11, 0, 0, 0, 0, 0, 0, 15, 12, 15, 13, 15, 14
            ]))
        );
        assert_eq!(
            Ip::parse("1:2::3:4:5:6:7".as_bytes()),
            Ok(Ip::new([0, 1, 0, 2, 0, 0, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7]))
        );
        assert_eq!(
            Ip::parse("1:2:3:4:5:6:7:8".as_bytes()),
            Ok(Ip::new([0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8]))
        );
        assert_eq!(
            Ip::parse("::1:2:3:4:5:6:7".as_bytes()),
            Ok(Ip::new([0, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7]))
        );
        assert_eq!(
            Ip::parse("ab:cd:ef:01:02::".as_bytes()),
            Ok(Ip::new([
                0, 171, 0, 205, 0, 239, 0, 1, 0, 2, 0, 0, 0, 0, 0, 0
            ]))
        );
        assert_eq!(
            Ip::parse("ab:cd:ef:01:02:03:04::".as_bytes()),
            Ok(Ip::new([
                0, 171, 0, 205, 0, 239, 0, 1, 0, 2, 0, 3, 0, 4, 0, 0
            ]))
        );
    }

    #[test]
    fn reject_invalid_ip6() {
        assert_eq!(
            Ip::parse("ab:cd:ef:01:02:03:04::1".as_bytes()),
            Err(Error::TooManyOctets),
        );
        assert_eq!(
            Ip::parse(":ab:cd:ef:01:23:45:67".as_bytes()),
            Err(Error::MissingOctet),
        );
        assert_eq!(
            Ip::parse(":ab:cd:ef:01:23:45:67:89".as_bytes()),
            Err(Error::MissingOctet),
        );
        assert_eq!(
            Ip::parse("ab:cd:ef:01:23:45:67:89:".as_bytes()),
            Err(Error::TooManyOctets),
        );
        assert_eq!(
            Ip::parse("ab:cd:ef:01:23:45:67:".as_bytes()),
            Err(Error::MissingOctet),
        );
    }
}
