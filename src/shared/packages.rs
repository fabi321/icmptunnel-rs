use crate::constants::{CHACHA20POLY1305_AUTH_OVERHEAD, CHACHA20_KEY_SIZE, MAX_PAYLOAD_SIZE, CHACHA20_NONCE_SIZE, HEADER_LEN, MTU};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305,
};
use sha3::digest::consts::U64;
use sha3::digest::generic_array::GenericArray;
use sha3::{Digest, Sha3_512};
use std::io;
use rand_core::RngCore;
use x25519_dalek::{PublicKey, ReusableSecret, SharedSecret};

fn hash_password_and_key(password: &str, key: &PublicKey) -> GenericArray<u8, U64> {
    // Initialize hasher
    let mut hasher = Sha3_512::new();

    // Feed data
    hasher.update(password.as_bytes());
    hasher.update(key.as_bytes());

    hasher.finalize()
}

fn encrypt_data<const S: usize, const O: usize>(plaintext: [u8; S], key: &[u8; 32]) -> [u8; O] {
    #[cfg(debug_assertions)]
    assert_eq!(S + CHACHA20_NONCE_SIZE + CHACHA20POLY1305_AUTH_OVERHEAD, O, "Invalid input and output size");
    let mut result = [0u8; O];
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    result[..CHACHA20_NONCE_SIZE].copy_from_slice(nonce.as_slice());

    // encrypt plaintext and add to end
    let cipher = ChaCha20Poly1305::new(key.into());
    // I have no clue, when this might fail
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_slice()).unwrap();
    result[CHACHA20_NONCE_SIZE..].copy_from_slice(ciphertext.as_slice());

    result
}

fn decrypt_data(ciphertext: &[u8], key: &[u8; 32]) -> io::Result<Vec<u8>> {
    // extract nonce
    let nonce: [u8; 12] = (&ciphertext[..CHACHA20_NONCE_SIZE]).try_into().unwrap();

    // initialize cipher
    let cipher = ChaCha20Poly1305::new(key.into());

    // Decrypt data
    cipher.decrypt(&nonce.into(), &ciphertext[CHACHA20_NONCE_SIZE..])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Decryption failed"))
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct AuthenticationRequest {
    pub dh_key: PublicKey,
}

impl AuthenticationRequest {
    /// 32 bytes for Diffie Hellman key + 64 bytes for SHA512 hash
    pub const SIZE: usize = 32 + 64;

    pub fn new(dh_key: PublicKey) -> AuthenticationRequest {
        AuthenticationRequest { dh_key }
    }

    pub fn to_bytes(self, password: &str) -> [u8; Self::SIZE] {
        let mut result = [0u8; Self::SIZE];

        // First 32 bytes are Diffie Hellman key
        result[..32].copy_from_slice(self.dh_key.as_bytes());

        // Calculate hash
        let hash = hash_password_and_key(password, &self.dh_key);

        // Set the has as the last 64 bytes
        result[32..].copy_from_slice(hash.as_slice());

        result
    }

    pub fn verified_from_bytes(bytes: &[u8], password: &str) -> io::Result<AuthenticationRequest> {
        if bytes.len() != Self::SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid packet length",
            ));
        }
        let dh_bytes: [u8; 32] = (&bytes[..32]).try_into().unwrap();
        let dh_key = PublicKey::from(dh_bytes);
        let hash = hash_password_and_key(password, &dh_key);
        if &bytes[32..] == hash.as_slice() {
            Ok(AuthenticationRequest { dh_key })
        } else {
            Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid hash"))
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct AuthenticationReply {
    pub dh_key: PublicKey,
    pub client_id: u8,
    pub session_id: u8,
    pub session_key: [u8; CHACHA20_KEY_SIZE],
}

impl AuthenticationReply {
    /// 32 bytes for Diffie Hellman key, 64 bytes password hash, one byte for client id,
    /// one byte for session id, 32 bytes for session key, nonce, authentication overhead
    pub const SIZE: usize =
        32 + 64 + 1 + 1 + CHACHA20_KEY_SIZE + 12 + CHACHA20POLY1305_AUTH_OVERHEAD;

    pub fn new(
        dh_key: PublicKey,
        client_id: u8,
        session_id: u8,
        session_key: &[u8; CHACHA20_KEY_SIZE],
    ) -> AuthenticationReply {
        AuthenticationReply {
            dh_key,
            client_id,
            session_id,
            session_key: session_key.clone(),
        }
    }

    pub fn to_bytes(self, dh_secret: &SharedSecret, password: &str) -> [u8; Self::SIZE] {
        let mut result = [0u8; Self::SIZE];

        // Add Diffie Hellman public key first
        result[..32].copy_from_slice(self.dh_key.as_bytes());

        // Calculate hash and put it after Diffie Hellman key
        let hash = hash_password_and_key(password, &self.dh_key);
        result[32..96].copy_from_slice(hash.as_slice());

        // Combine plaintext
        let mut plaintext = [0u8; 2 + CHACHA20_KEY_SIZE];
        plaintext[0] = self.client_id;
        plaintext[1] = self.session_id;
        plaintext[2..(2 + CHACHA20_KEY_SIZE)].copy_from_slice(self.session_key.as_slice());

        // Encrypt and store data
        let ciphertext: [u8; Self::SIZE - 96] = encrypt_data(plaintext, dh_secret.as_bytes());
        result[96..].copy_from_slice(ciphertext.as_slice());

        result
    }

    /// Private key for this has to be a reusable secret due to the possibility of receiving
    /// multiple replies before the correct one
    pub fn verified_from_bytes(
        bytes: &[u8],
        private_key: &ReusableSecret,
        password: &str,
    ) -> io::Result<AuthenticationReply> {
        if bytes.len() != Self::SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid packet length",
            ));
        }

        // Get Diffie Hellman public key of other side
        let dh_bytes: [u8; 32] = (&bytes[..32]).try_into().unwrap();
        let dh_key = PublicKey::from(dh_bytes);

        // Calculate shared secret based on keys
        let shared_secret = private_key.diffie_hellman(&dh_key);

        // Check if server is authentic by checking the hash
        let hash = hash_password_and_key(password, &dh_key);
        if hash.as_slice() != &bytes[32..96] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid password hash",
            ));
        }

        // decrypt data
        let plaintext = decrypt_data(&bytes[96..], shared_secret.as_bytes())?;

        // demangle plaintext
        let client_id = plaintext[0];
        let session_id = plaintext[1];
        let session_key = (&plaintext[2..]).try_into().unwrap();
        Ok(AuthenticationReply {
                dh_key,
                client_id,
                session_id,
                session_key,
        })
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct SessionExtension {
    pub new_key: [u8; 32],
    pub session_id: u8,
}

impl SessionExtension {
    pub const SIZE: usize = CHACHA20_NONCE_SIZE + CHACHA20POLY1305_AUTH_OVERHEAD + 32 + 1;

    pub fn new(new_key: [u8; 32], session_id: u8) -> SessionExtension {
        SessionExtension { new_key, session_id }
    }

    pub fn to_bytes(self, key: &[u8; 32]) -> [u8; Self::SIZE] {
        let mut plaintext = [0u8; 33];
        plaintext[..32].copy_from_slice(self.new_key.as_slice());
        plaintext[32] = self.session_id;

        encrypt_data(plaintext, key)
    }

    pub fn verified_from_bytes(
        bytes: &[u8],
        key: &[u8; 32],
    ) -> io::Result<SessionExtension> {
        if bytes.len() != Self::SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid packet length",
            ));
        }

        let plaintext = decrypt_data(bytes, key)?;

        let new_key = (&plaintext[..32]).try_into().unwrap();
        let session_id = plaintext[32];

        Ok(SessionExtension { new_key, session_id })
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct DataPacket {
    pub data: Vec<u8>,
}

impl DataPacket {
    /// Max payload size + poly1305 auth overhead + chacha20 nonce + payload_size header
    pub const SIZE: usize = MAX_PAYLOAD_SIZE + CHACHA20POLY1305_AUTH_OVERHEAD + CHACHA20_NONCE_SIZE + HEADER_LEN;

    pub fn new(data: Vec<u8>) -> DataPacket {
        DataPacket { data }
    }

    pub fn to_bytes(self, key: &[u8; 32]) -> io::Result<[u8; Self::SIZE]> {
        if self.data.len() > MAX_PAYLOAD_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Data too long for one packet"
            ))
        }

        // Prepare plain text by inserting length and content
        let mut plaintext = [0u8; MAX_PAYLOAD_SIZE + HEADER_LEN];
        plaintext[0..2].copy_from_slice(&(self.data.len() as u16).to_be_bytes());
        plaintext[2..(2 + self.data.len())].copy_from_slice(self.data.as_slice());

        // fill unused bytes with random data to prevent known plaintext attacks due to constant
        // size packets
        OsRng.fill_bytes(&mut plaintext[2 + self.data.len()..]);

        Ok(encrypt_data(plaintext, key))
    }

    pub fn verified_from_bytes(
        bytes: &[u8],
        key: &[u8; 32],
    ) -> io::Result<DataPacket> {
        if bytes.len() != Self::SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid packet length",
            ));
        }

        let plaintext = decrypt_data(bytes, key)?;

        // Reconstruct vec
        let length = u16::from_be_bytes((&plaintext[0..2]).try_into().unwrap());
        let data = Vec::from(&plaintext[2..length as usize + 2]);
        Ok(DataPacket { data })
    }
}

#[cfg(test)]
mod tests {
    use x25519_dalek::EphemeralSecret;
    use super::*;

    #[test]
    fn test_handshake() {
        let alice_private_key = ReusableSecret::random_from_rng(&mut OsRng);
        let alice_pub_key = PublicKey::from(&alice_private_key);
        let password = "password".to_string();
        let alice_auth_request = AuthenticationRequest::new(alice_pub_key.clone());
        let auth_request_bytes = alice_auth_request.clone().to_bytes(&password);
        assert_eq!(auth_request_bytes.len(), AuthenticationRequest::SIZE);
        let bob_auth_request =
            AuthenticationRequest::verified_from_bytes(&auth_request_bytes, &password)
                .expect("error decoding auth request");
        assert_eq!(
            alice_auth_request, bob_auth_request,
            "Received auth request differs from sent auth request"
        );
        let bob_private_key = EphemeralSecret::random_from_rng(&mut OsRng);
        let bob_public_key = PublicKey::from(&bob_private_key);
        let bob_shared_key = bob_private_key.diffie_hellman(&bob_auth_request.dh_key);
        let bob_auth_reply = AuthenticationReply::new(bob_public_key.clone(), 1, 2, &[0u8; 32]);
        let auth_reply_bytes = bob_auth_reply.clone().to_bytes(&bob_shared_key, &password);
        assert_eq!(auth_reply_bytes.len(), AuthenticationReply::SIZE);
        let alice_auth_reply = AuthenticationReply::verified_from_bytes(
            auth_reply_bytes.as_slice(),
            &alice_private_key,
            &password,
        )
        .expect("error decoding auth reply");
        assert_eq!(
            bob_auth_reply, alice_auth_reply,
            "Received auth reply differs from sent auth reply"
        );
    }

    #[test]
    fn test_mallory() {
        let alice_private_key = ReusableSecret::random_from_rng(&mut OsRng);
        let alice_pub_key = PublicKey::from(&alice_private_key);
        let password = "password".to_string();
        let alice_auth_request = AuthenticationRequest::new(alice_pub_key.clone());
        let auth_request_bytes = alice_auth_request.clone().to_bytes(&password);
        // Mallory only knows pub key of alice and uses a different password
        let dh_bytes: [u8; 32] = (&auth_request_bytes[..32]).try_into().unwrap();
        let dh_key = PublicKey::from(dh_bytes);
        let mallory_password = "different password".to_string();
        let mallory_private_key = EphemeralSecret::random_from_rng(&mut OsRng);
        let mallory_public_key = PublicKey::from(&mallory_private_key);
        let mallory_shared_key = mallory_private_key.diffie_hellman(&dh_key);
        let mallory_auth_reply =
            AuthenticationReply::new(mallory_public_key.clone(), 1, 2, &[0u8; 32]);
        let auth_reply_bytes = mallory_auth_reply
            .clone()
            .to_bytes(&mallory_shared_key, &mallory_password);
        let alice_auth_reply = AuthenticationReply::verified_from_bytes(
            auth_reply_bytes.as_slice(),
            &alice_private_key,
            &password,
        );
        assert!(
            alice_auth_reply.is_err(),
            "Mallory was able to establish a connection to alice"
        )
    }

    #[test]
    fn test_short_byte_inputs() {
        let password = "password".to_string();
        let result = AuthenticationRequest::verified_from_bytes(
            &[0u8; AuthenticationRequest::SIZE - 1],
            &password,
        );
        assert!(
            result.is_err(),
            "AuthenticationRequest accepted too short packet"
        );
        let result = AuthenticationRequest::verified_from_bytes(
            &[0u8; AuthenticationRequest::SIZE + 1],
            &password,
        );
        assert!(
            result.is_err(),
            "AuthenticationRequest accepted too long packet"
        );
        let key = ReusableSecret::random_from_rng(&mut OsRng);
        let result = AuthenticationReply::verified_from_bytes(
            &[0u8; AuthenticationReply::SIZE - 1],
            &key,
            &password,
        );
        assert!(
            result.is_err(),
            "AuthenticationReply accepted too short packet"
        );
        let key = ReusableSecret::random_from_rng(&mut OsRng);
        let result = AuthenticationReply::verified_from_bytes(
            &[0u8; AuthenticationReply::SIZE + 1],
            &key,
            &password,
        );
        assert!(
            result.is_err(),
            "AuthenticationReply accepted too long packet"
        );
    }

    #[test]
    fn test_data_packet() {
        let key: [u8; 32] = *ChaCha20Poly1305::generate_key(&mut OsRng).as_ref();
        let data = Vec::from([0u8; MAX_PAYLOAD_SIZE + 1].as_slice());
        let packet = DataPacket::new(data);
        let result = packet.to_bytes(&key);
        assert!(result.is_err(), "DataPacket accepted too long input");
        let data = Vec::from([0u8; MAX_PAYLOAD_SIZE].as_slice());
        let packet = DataPacket::new(data);
        let bytes = packet.clone().to_bytes(&key).expect("Failed to compile packet");
        let received_packet = DataPacket::verified_from_bytes(&bytes, &key).expect("Failed to parse packet");
        assert_eq!(packet, received_packet, "Packets differ");
        let data = Vec::from([0u8; 50].as_slice());
        let packet = DataPacket::new(data);
        let bytes = packet.clone().to_bytes(&key).expect("Failed to compile packet");
        let received_packet = DataPacket::verified_from_bytes(&bytes, &key).expect("Failed to parse packet");
        assert_eq!(packet, received_packet, "Packets differ");
    }
}
