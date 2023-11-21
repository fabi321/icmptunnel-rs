pub const IPV4_HEADER_LEN: usize = 20;

pub const ICMP_HEADER_LEN: usize = 8;

pub const MTU: usize = 1500;

// payload_length header
pub const HEADER_LEN: usize = 2;

pub const CHACHA20_KEY_SIZE: usize = 32;

pub const CHACHA20_NONCE_SIZE: usize = 12;

// Overhead due to chacha20poly1305 authentication tag
pub const CHACHA20POLY1305_AUTH_OVERHEAD: usize = 16;

pub const MAX_PAYLOAD_SIZE: usize = MTU
    - IPV4_HEADER_LEN
    - ICMP_HEADER_LEN
    - HEADER_LEN
    - CHACHA20POLY1305_AUTH_OVERHEAD
    - CHACHA20_NONCE_SIZE;
