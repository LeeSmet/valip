use crate::errors::Error;
use crate::ip4::ip::IPv4;

/// A CIDR represented by a prefix and a mask
#[derive(Debug, PartialEq, Eq)]
pub struct CIDR {
    prefix: [u8; 4],
    mask: u8,
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
        IPv4::new(self.prefix).is_public()
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

        let prefix = IPv4::parse(&input[..sep_pos])?.as_octets();

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
    pub const fn contains(&self, ip: IPv4) -> bool {
        let mask_bits = self.as_bitmask();

        ip.as_bits() & mask_bits == IPv4::new(self.prefix).as_bits() & mask_bits
    }
}

#[cfg(test)]
mod tests {
    use crate::errors::Error;
    use crate::ip4::ip::IPv4;

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
                .contains(IPv4::parse("34.0.0.254".as_bytes()).unwrap()),
            true,
        );
        assert_eq!(
            super::CIDR::parse("34.0.1.1/24".as_bytes())
                .unwrap()
                .contains(IPv4::parse("34.0.0.254".as_bytes()).unwrap()),
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
