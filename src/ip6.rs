use core::ops::Deref;

use crate::errors::Error;
use crate::hex::hex_byte_to_byte_value;

const IP_BYTES: usize = 16;

/// List of all private subnets.
///
/// An IP is considered public if it is not part of a private range. Private ranges are considered
/// to be:
///
/// - 100::/64: Discard prefix
/// - fc00::/7: Private network
/// - fe80::/10: Link local address
const PRIVATE_IP6_SUBNETS: [CIDR; 3] = [
    CIDR::new([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 64),
    CIDR::new([252, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 7),
    CIDR::new([254, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 10),
];

/// A plain IPv6 address without network mask.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Ip {
    octets: [u8; IP_BYTES],
}

/// A CIDR represented by a prefix and a mask
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CIDR {
    ip: Ip,
    mask: u8,
}

impl Ip {
    /// Create a new IPv6 address with the given octets.
    #[inline]
    pub const fn new(octets: [u8; IP_BYTES]) -> Ip {
        Ip { octets }
    }

    /// Extracts the octets from the IP as a byte array.
    #[inline]
    pub const fn as_octets(&self) -> [u8; IP_BYTES] {
        self.octets
    }

    /// Checks if an IP is unicast or not.
    #[inline]
    pub const fn is_unicast(&self) -> bool {
        // Multicast has high order byte set to all 1 bits.
        self.octets[0] != u8::MAX
    }

    /// Interpret the IP address as the bit sequence
    #[inline]
    pub const fn as_bits(&self) -> u128 {
        (self.octets[0] as u128) << 120
            | (self.octets[1] as u128) << 112
            | (self.octets[2] as u128) << 104
            | (self.octets[3] as u128) << 96
            | (self.octets[4] as u128) << 88
            | (self.octets[5] as u128) << 80
            | (self.octets[6] as u128) << 72
            | (self.octets[7] as u128) << 64
            | (self.octets[8] as u128) << 56
            | (self.octets[9] as u128) << 48
            | (self.octets[10] as u128) << 40
            | (self.octets[11] as u128) << 32
            | (self.octets[12] as u128) << 24
            | (self.octets[13] as u128) << 16
            | (self.octets[14] as u128) << 8
            | (self.octets[15] as u128)
    }

    /// Checks if an IP is in the public ranges or not.
    pub fn is_public(&self) -> bool {
        for pip in &PRIVATE_IP6_SUBNETS {
            // Ensure only part of the prefix is set
            if self.as_bits() & pip.as_bitmask() == pip.as_ip().as_bits() {
                return false;
            }
        }

        true
    }

    /// Parses ACII input bytes to an IPv6 address.
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

impl CIDR {
    /// Create a new CIDR from octets and a mask.
    ///
    /// # Panics
    ///
    /// This function panics if mask is higher than 128.
    #[inline]
    pub const fn new(octets: [u8; IP_BYTES], mask: u8) -> CIDR {
        if mask > 128 {
            panic!("CIDR mask can't be higher than 128");
        }

        CIDR {
            ip: Ip::new(octets),
            mask,
        }
    }

    /// Extracts the ip from the CIDR.
    #[inline]
    pub const fn as_ip(&self) -> Ip {
        self.ip
    }

    /// Extracts the mask from the CIDR as a byte.
    #[inline]
    pub const fn as_mask(&self) -> u8 {
        self.mask
    }

    /// Checks if an IP is unicast or not.
    #[inline]
    pub const fn is_unicast(&self) -> bool {
        // Multicast has high order byte set to all 1 bits.
        self.ip.is_unicast()
    }

    /// Get the mask value as bitmask with the fixed bits set (111...000).
    #[inline]
    pub const fn as_bitmask(&self) -> u128 {
        // Special condition to avoid an overvlow
        if self.mask == 0 {
            u128::MAX
        } else {
            !(2_u128.pow(128 - self.mask as u32) - 1)
        }
    }

    /// Checks if an IP is in the public ranges or not.
    #[inline]
    pub fn is_public(&self) -> bool {
        self.ip.is_public()
    }

    /// Parses ASCII input bytes to an IPv6 in CIDR notation.
    pub fn parse(input: &[u8]) -> Result<CIDR, Error> {
        // Input can be at most 43 bytes.
        if input.len() > 43 {
            return Err(Error::InputTooLong);
        }

        let sep_pos = if let Some(pos) = input.iter().position(|c| c == &b'/') {
            pos
        } else {
            return Err(Error::MissingMask);
        };

        let ip = Ip::parse(&input[..sep_pos])?;

        let mask_input = &input[sep_pos + 1..];
        if mask_input.len() > 3 {
            return Err(Error::InputTooLong);
        }
        if mask_input.is_empty() {
            return Err(Error::InputTooShort);
        }

        let mut mask: u8 = 0;
        for c in mask_input {
            match c {
                b'0'..=b'9' => {
                    mask = match mask.checked_mul(10) {
                        Some(mask) => mask,
                        None => return Err(Error::MaskOverflow),
                    };
                    mask = match mask.checked_add(c - b'0') {
                        Some(mask) => mask,
                        None => return Err(Error::MaskOverflow),
                    };
                }
                _ => return Err(Error::IllegalCharacter),
            }
        }

        // 128 bits max in an IPv6, also if mask is 0 it must be single digit.
        if mask > 128 {
            return Err(Error::MaskOverflow);
        }
        if mask == 0 && mask_input.len() > 1 {
            return Err(Error::LeadingZero);
        }

        Ok(CIDR { ip, mask })
    }

    /// Checks if an [`Ip`] is contained in this subnet.
    #[inline]
    pub const fn contains(&self, ip: Ip) -> bool {
        let mask_bits = self.as_bitmask();

        ip.as_bits() & mask_bits == self.ip.as_bits() & mask_bits
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
    use super::{Ip, CIDR};
    use crate::errors::Error;

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

    #[test]
    fn parse_cidr() {
        assert_eq!(
            CIDR::parse("2a10:b600:1::0cc4:7a30:65b5/64".as_bytes()),
            Ok(CIDR::new(
                [42, 16, 182, 0, 0, 1, 0, 0, 0, 0, 12, 196, 122, 48, 101, 181],
                64
            ))
        );
    }
}
