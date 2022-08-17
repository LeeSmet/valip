# valip

Small toolset to parse IP addresses and CIDR's from strings in no-std environments.
Both IPv4 and IPv6 is supported, although currently IPv6 does not support decoding
of IP addresses (and CIDR's) with an embedded IPv4 address (e.g. `64:ff9b::192.0.2.128`).

Additionally, Mac addresses can also be parsed, though this is mostly for verification
purposes that "some" input is indeed a valid Mac address.

In this context, strings are represented by the ASCII bytes.
