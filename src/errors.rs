/// Collection of all errors that can be encountered when using this crate
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Input is too short to be able to extract valid data.
    InputTooShort,
    /// Input is longer than possible for valid data.
    InputTooLong,
    /// A leading zero was found.
    LeadingZero,
    /// The value was too high to be a valid octet (input size > 255).
    OctetOverflow,
    /// There is no data for an octet, this essentially means 2 '.' characters appeared back to
    /// back, or the input data ends with a '.' character (omitting the last octet).
    MissingOctet,
    /// There are too many octets in the input. For an IPv4 address, the amount of octets must always
    /// be 4.
    TooManyOctets,
    /// A character in the input which can't be parsed.
    IllegalCharacter,
    /// There are not enough octets in the input data.
    InsufficientOctets,
    /// There is no mask in the input data
    MissingMask,
    /// Value of the mask field is too large, this can be at most 32.
    MaskOverflow,
    /// A sequence of zero section is omitted twice in an ipv6 address leading to ambiguity (2 "::"
    /// occurrences).
    DoubleOmission,
}
