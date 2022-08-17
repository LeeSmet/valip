pub mod cidr;
pub mod ip;

use crate::errors::Error;
use core::ops::Deref;

/// List of all private subnets.
///
/// An IP is considered public if it is not part of a private range. Private ranges are considered
/// to be:
///
/// - 0.0.0.0/8 - current network
/// - 10.0.0.0/8 - private network
/// - 100.64.0.0/10 - carrier grade NAT
/// - 127.0.0.0/8 - loopback addresses
/// - 169.254.0.0/16 - link-local addresses
/// - 172.16.0.0/12 - private network
/// - 192.0.2.0/24 - TEST-NET-1, documentation and examples
/// - 192.168.0.0/16 - private network
/// - 198.18.0.0/15 - private -network - benchmark testing inter-networking
/// - 198.51.100.0/24 - TEST-NET-2, documentation and examples
/// - 203.0.113.0/24 - TEST-NET-3, documentation and examples
/// - 255.255.255.255/32 - Limited broadcast range
const PRIVATE_IP4_SUBNETS: [CIDR; 12] = [
    CIDR::new([0, 0, 0, 0], 8),
    CIDR::new([10, 0, 0, 0], 8),
    CIDR::new([100, 64, 0, 0], 10),
    CIDR::new([127, 0, 0, 0], 8),
    CIDR::new([169, 254, 0, 0], 16),
    CIDR::new([172, 16, 0, 0], 12),
    CIDR::new([192, 0, 2, 0], 24),
    CIDR::new([192, 168, 0, 0], 16),
    CIDR::new([198, 18, 0, 0], 15),
    CIDR::new([198, 51, 100, 0], 24),
    CIDR::new([203, 0, 113, 0], 24),
    CIDR::new([255, 255, 255, 255], 32),
];

/// A plain IPv4 address without network mask.
#[derive(Debug, PartialEq, Eq)]
pub struct Ip {
    octets: [u8; 4],
}

/// A CIDR represented by a prefix and a mask
#[derive(Debug, PartialEq, Eq)]
pub struct CIDR {
    prefix: [u8; 4],
    mask: u8,
}

impl Ip {
    /// Create a new IPv4 address with the given octets.
    #[inline]
    pub const fn new(octets: [u8; 4]) -> Ip {
        Ip { octets }
    }

    /// Extracts the octets from the IP as a byte array.
    #[inline]
    pub const fn as_octets(&self) -> [u8; 4] {
        self.octets
    }

    /// Interpret the IP address as the bit sequence
    #[inline]
    pub const fn as_bits(&self) -> u32 {
        (self.octets[0] as u32) << 24
            | (self.octets[1] as u32) << 16
            | (self.octets[2] as u32) << 8
            | (self.octets[3] as u32)
    }

    /// Checks if an IP is unicast or not.
    ///
    /// Technically this can still be an anycast IP, for instance 1.1.1.1 or 8.8.8.8, but there is
    /// no functional difference from the client perspective.
    #[inline]
    pub const fn is_unicast(&self) -> bool {
        // 224.0.0.0/4 -> multicast range.
        // 240.0.0.0/4 -> reserved for future use.
        // Hence we consider all the remaining to be unicast.
        self.octets[0] < 224
    }

    /// Checks if an IP is in the public ranges or not.
    pub fn is_public(&self) -> bool {
        for pip in &PRIVATE_IP4_SUBNETS {
            // Ensure only part of the prefix is set
            if self.as_bits() & pip.as_bitmask() == Ip::new(pip.as_prefix()).as_bits() {
                return false;
            }
        }

        true
    }

    /// Parses ACII input bytes to an IPv4 address.
    pub fn parse(input: &[u8]) -> Result<Ip, Error> {
        if input.len() < 7 {
            return Err(Error::InputTooShort);
        }

        if input.len() > 15 {
            return Err(Error::InputTooLong);
        }

        let mut sections = 0;
        // See below why this is true
        let mut last_char_was_dot = true;
        let mut octets = [0, 0, 0, 0];
        // Use a u8 accumulator since octests are u8. This way we can use checked operations, and if we
        // have an overflow we know there is an invalid value;
        let mut accumulator: u8 = 0;

        for c in input {
            match c {
                b'0'..=b'9' => {
                    // Don't allow leading digits 0.
                    // Need to allow single 0 digits though. Instead if doing a look ahead for a '.'
                    // character, we fail if accumulator is at 0 and the last char was not a dot.
                    // This works because we start with the last_char_was_dot flag set to true.
                    if accumulator == 0 && !last_char_was_dot {
                        return Err(Error::LeadingZero);
                    }
                    accumulator = if let Some(a) = accumulator.checked_mul(10) {
                        a
                    } else {
                        return Err(Error::OctetOverflow);
                    };
                    accumulator = if let Some(a) = accumulator.checked_add(c - b'0') {
                        a
                    } else {
                        return Err(Error::OctetOverflow);
                    };

                    // clear flag
                    last_char_was_dot = false;
                }
                b'.' => {
                    if last_char_was_dot {
                        return Err(Error::MissingOctet);
                    }

                    // set octet value
                    octets[sections] = accumulator;

                    // advance section
                    sections += 1;
                    accumulator = 0;

                    // shield if there are too many sections
                    if sections > 3 {
                        return Err(Error::TooManyOctets);
                    }

                    // set flag
                    last_char_was_dot = true;
                }
                _ => return Err(Error::IllegalCharacter),
            }
        }

        // At this point the last section can't be saved yet
        octets[sections] = accumulator;

        // Sections must only be 3 here since we have 0 based indexing
        if sections < 3 {
            Err(Error::InsufficientOctets)
        } else if last_char_was_dot {
            Err(Error::MissingOctet)
        } else {
            Ok(Ip { octets })
        }
    }
}

impl Deref for Ip {
    type Target = [u8; 4];

    fn deref(&self) -> &Self::Target {
        &self.octets
    }
}

impl CIDR {
    /// Create a new CIDR from octets and a mask.
    ///
    /// # Panics
    ///
    /// This function panics if mask is higher than 32.
    #[inline]
    pub const fn new(prefix: [u8; 4], mask: u8) -> CIDR {
        if mask > 32 {
            panic!("CIDR mask can't be higher than 32");
        }

        CIDR { prefix, mask }
    }

    /// Extracts the prefix from the CIDR as a byte array.
    #[inline]
    pub const fn as_prefix(&self) -> [u8; 4] {
        self.prefix
    }

    /// Extracts the mask from the CIDR as a byte.
    #[inline]
    pub const fn as_mask(&self) -> u8 {
        self.mask
    }

    /// Checks if an IP is unicast or not.
    ///
    /// Technically this can still be an anycast IP, for instance 1.1.1.1 or 8.8.8.8, but there is
    /// no functional difference from the client perspective.
    #[inline]
    pub const fn is_unicast(&self) -> bool {
        // 224.0.0.0/4 -> multicast range.
        // 240.0.0.0/4 -> reserved for future use.
        // Hence we consider all the remaining to be unicast.
        self.prefix[0] < 224
    }

    /// Get the mask value as bitmask with the fixed bits set (111...000).
    #[inline]
    pub const fn as_bitmask(&self) -> u32 {
        // u64 so we don't have overflow on /32
        // TODO: benchmark if looping with shifts is faster
        !((2_u64.pow(32 - self.mask as u32) - 1) as u32)
    }

    /// Checks if an IP is in the public ranges or not.
    #[inline]
    pub fn is_public(&self) -> bool {
        Ip::new(self.prefix).is_public()
    }

    /// Parses ASCII input bytes to an IPv4 in CIDR notation.
    pub fn parse(input: &[u8]) -> Result<CIDR, Error> {
        // Input can be at most 18 bytes.
        if input.len() > 18 {
            return Err(Error::InputTooLong);
        }

        let sep_pos = if let Some(pos) = input.iter().position(|c| c == &b'/') {
            pos
        } else {
            return Err(Error::MissingMask);
        };

        let prefix = Ip::parse(&input[..sep_pos])?.as_octets();

        let mask_input = &input[sep_pos + 1..];
        if mask_input.len() > 2 {
            return Err(Error::InputTooLong);
        }
        if mask_input.is_empty() {
            return Err(Error::InputTooShort);
        }

        let mut mask: u8 = 0;
        for c in mask_input {
            match c {
                b'0'..=b'9' => {
                    // only 2 digits max so we can never overflow a u8, no need for checked mul and add.
                    mask *= 10;
                    mask += c - b'0';
                }
                _ => return Err(Error::IllegalCharacter),
            }
        }

        // 32 bits max in an IPv4, also if mask is 0 it must be single digit.
        if mask > 32 {
            return Err(Error::MaskOverflow);
        }
        if mask == 0 && mask_input.len() > 1 {
            return Err(Error::LeadingZero);
        }

        Ok(CIDR { prefix, mask })
    }

    /// Checks if an IP is contained in a given CIDR.
    #[inline]
    pub const fn contains(&self, ip: Ip) -> bool {
        let mask_bits = self.as_bitmask();

        ip.as_bits() & mask_bits == Ip::new(self.prefix).as_bits() & mask_bits
    }
}

#[cfg(test)]
mod tests {
    use crate::errors::Error;

    #[test]
    fn parse_valid_ips() {
        assert_eq!(
            super::Ip::parse("1.1.1.1".as_bytes()),
            Ok(super::Ip::new([1, 1, 1, 1]))
        );
        assert_eq!(
            super::Ip::parse("100.200.10.0".as_bytes()),
            Ok(super::Ip::new([100, 200, 10, 0]))
        );
        assert_eq!(
            super::Ip::parse("255.255.255.255".as_bytes()),
            Ok(super::Ip::new([255, 255, 255, 255]))
        );
        assert_eq!(
            super::Ip::parse("0.0.0.0".as_bytes()),
            Ok(super::Ip::new([0, 0, 0, 0]))
        );
    }

    #[test]
    fn reject_invalid_ips() {
        assert_eq!(
            super::Ip::parse("1.1.1.1.".as_bytes()),
            Err(Error::TooManyOctets)
        );
        assert_eq!(
            super::Ip::parse("1.1.1.1.1".as_bytes()),
            Err(Error::TooManyOctets)
        );
        assert_eq!(
            super::Ip::parse("1.1.1.".as_bytes()),
            Err(Error::InputTooShort)
        );
        assert_eq!(
            super::Ip::parse("1.1.1".as_bytes()),
            Err(Error::InputTooShort)
        );
        assert_eq!(
            super::Ip::parse("100.100.1".as_bytes()),
            Err(Error::InsufficientOctets)
        );
        assert_eq!(
            super::Ip::parse("100.100.1.".as_bytes()),
            Err(Error::MissingOctet)
        );
        assert_eq!(
            super::Ip::parse("255.255.255.256".as_bytes()),
            Err(Error::OctetOverflow)
        );
        assert_eq!(
            super::Ip::parse("256.255.255.255".as_bytes()),
            Err(Error::OctetOverflow)
        );
        assert_eq!(
            super::Ip::parse("1.10.100.1000".as_bytes()),
            Err(Error::OctetOverflow)
        );
        assert_eq!(
            super::Ip::parse("1000.100.10.1".as_bytes()),
            Err(Error::OctetOverflow)
        );
        assert_eq!(
            super::Ip::parse("af.fe.ff.ac".as_bytes()),
            Err(Error::IllegalCharacter)
        );
        assert_eq!(
            super::Ip::parse("00.0.0.0".as_bytes()),
            Err(Error::LeadingZero)
        );
        assert_eq!(
            super::Ip::parse("1.01.2.3".as_bytes()),
            Err(Error::LeadingZero)
        );
        assert_eq!(
            super::Ip::parse("1:1:1:1".as_bytes()),
            Err(Error::IllegalCharacter)
        );
        assert_eq!(
            super::Ip::parse("1.1.2_.3".as_bytes()),
            Err(Error::IllegalCharacter)
        );
    }

    #[test]
    fn public_ip() {
        // Technically unicast but yeah
        assert_eq!(
            super::Ip::parse("1.1.1.1".as_bytes()).unwrap().is_public(),
            true
        );
        assert_eq!(
            super::Ip::parse("10.10.100.254".as_bytes())
                .unwrap()
                .is_public(),
            false
        );
        assert_eq!(
            super::Ip::parse("10.10.100.254".as_bytes())
                .unwrap()
                .is_public(),
            false
        );
        assert_eq!(
            super::Ip::parse("172.10.100.254".as_bytes())
                .unwrap()
                .is_public(),
            true
        );
        assert_eq!(
            super::Ip::parse("172.20.100.254".as_bytes())
                .unwrap()
                .is_public(),
            false
        );
    }

    #[test]
    fn create_new_cidr() {
        super::CIDR::new([1, 1, 1, 1], 15);
    }

    #[test]
    #[should_panic]
    fn reject_large_mask() {
        super::CIDR::new([1, 1, 1, 1], 33);
    }

    #[test]
    fn accept_valid_cidr() {
        assert_eq!(
            super::CIDR::parse("1.1.1.1/32".as_bytes()),
            Ok(super::CIDR::new([1, 1, 1, 1], 32))
        );
        assert_eq!(
            super::CIDR::parse("1.1.1.1/1".as_bytes()),
            Ok(super::CIDR::new([1, 1, 1, 1], 1))
        );
        assert_eq!(
            super::CIDR::parse("255.255.255.255/32".as_bytes()),
            Ok(super::CIDR::new([255, 255, 255, 255], 32))
        );
        assert_eq!(
            super::CIDR::parse("255.255.255.129/25".as_bytes()),
            Ok(super::CIDR::new([255, 255, 255, 129], 25))
        );
        assert_eq!(
            super::CIDR::parse("128.0.0.0/1".as_bytes()),
            Ok(super::CIDR::new([128, 0, 0, 0,], 1))
        );
        assert_eq!(
            super::CIDR::parse("32.40.50.24/29".as_bytes()),
            Ok(super::CIDR::new([32, 40, 50, 24], 29))
        );
        assert_eq!(
            super::CIDR::parse("10.0.0.1/8".as_bytes()),
            Ok(super::CIDR::new([10, 0, 0, 1], 8))
        );
    }

    #[test]
    fn reject_invalid_cidr() {
        assert_eq!(
            super::CIDR::parse("1.1.1.1/33".as_bytes()),
            Err(Error::MaskOverflow)
        );
        assert_eq!(
            super::CIDR::parse("255.255.255.255/00".as_bytes()),
            Err(Error::LeadingZero)
        );
        assert_eq!(
            super::CIDR::parse("1.1.1.1//1".as_bytes()),
            Err(Error::IllegalCharacter)
        );
        assert_eq!(
            super::CIDR::parse("50.40.50.23/160".as_bytes()),
            Err(Error::InputTooLong)
        );
        assert_eq!(
            super::CIDR::parse("1.1.1.1/".as_bytes()),
            Err(Error::InputTooShort)
        );
        assert_eq!(
            super::CIDR::parse("1.111.1.1/".as_bytes()),
            Err(Error::InputTooShort)
        );
        assert_eq!(
            super::CIDR::parse("1.1.1.1/000".as_bytes()),
            Err(Error::InputTooLong)
        );
        assert_eq!(
            super::CIDR::parse("1.1.1.1/99".as_bytes()),
            Err(Error::MaskOverflow)
        );
        assert_eq!(
            super::CIDR::parse("1.1.1.1".as_bytes()),
            Err(Error::MissingMask)
        );
        assert_eq!(
            super::CIDR::parse("100.1.1.1".as_bytes()),
            Err(Error::MissingMask)
        );
        assert_eq!(
            super::CIDR::parse("1.1.1.1032".as_bytes()),
            Err(Error::MissingMask)
        );
        assert_eq!(
            super::CIDR::parse("1.1.1.1032/".as_bytes()),
            Err(Error::OctetOverflow)
        );
        assert_eq!(
            super::CIDR::parse("1.1.1.1/.".as_bytes()),
            Err(Error::IllegalCharacter)
        );
    }

    #[test]
    fn ip_in_cidr() {
        assert_eq!(
            super::CIDR::parse("34.0.0.1/24".as_bytes())
                .unwrap()
                .contains(super::Ip::parse("34.0.0.254".as_bytes()).unwrap()),
            true,
        );
        assert_eq!(
            super::CIDR::parse("34.0.1.1/24".as_bytes())
                .unwrap()
                .contains(super::Ip::parse("34.0.0.254".as_bytes()).unwrap()),
            false
        );
    }

    #[test]
    fn public_ip_cidr() {
        // Technically unicast but yeah
        assert_eq!(
            super::CIDR::parse("1.1.1.1/32".as_bytes())
                .unwrap()
                .is_public(),
            true,
        );
        assert_eq!(
            super::CIDR::parse("10.10.100.254/24".as_bytes())
                .unwrap()
                .is_public(),
            false,
        );
        assert_eq!(
            super::CIDR::parse("10.10.100.254/24".as_bytes())
                .unwrap()
                .is_public(),
            false,
        );
        assert_eq!(
            super::CIDR::parse("172.10.100.254/24".as_bytes())
                .unwrap()
                .is_public(),
            true,
        );
        assert_eq!(
            super::CIDR::parse("172.20.100.254/24".as_bytes())
                .unwrap()
                .is_public(),
            false,
        );
    }
}
