use std::fmt;

use rand::{thread_rng, Rng};
use sha2::digest::Digest;
use unsigned_varint::{decode, encode};

const SHA256_CODE: u16 = 0x12;
const SHA256_SIZE: u8 = 32;

/// Identifier of a peer of the network
///
/// The data is a hash of the public key of the peer
#[derive(Clone, PartialOrd, PartialEq, Eq, Hash)]
pub struct PeerId {
    inner: Vec<u8>,
}

impl PeerId {
    /// If data is a valid `PeerId`, return `PeerId`, else return error
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, ()> {
        if data.is_empty() {
            return Err(());
        }

        let (code, bytes) = decode::u16(&data).map_err(|_| ())?;

        if code != SHA256_CODE {
            return Err(());
        }

        if bytes.len() != SHA256_SIZE as usize + 1 {
            return Err(());
        }

        if bytes[0] != SHA256_SIZE {
            return Err(());
        }

        Ok(PeerId { inner: data })
    }

    /// Return a random `PeerId`
    pub fn random() -> Self {
        let mut seed = [0u8; 20];
        thread_rng().fill(&mut seed[..]);
        Self::from_seed(&seed)
    }

    /// Return `PeerId` which used hashed seed as inner.
    fn from_seed(seed: &[u8]) -> Self {
        let mut buf = encode::u16_buffer();
        let code = encode::u16(SHA256_CODE, &mut buf);

        let header_len = code.len() + 1;

        let mut inner = Vec::new();
        inner.resize(header_len + SHA256_SIZE as usize, 0);
        inner[..code.len()].copy_from_slice(code);
        inner[code.len()] = SHA256_SIZE;

        let mut hasher = sha2::Sha256::default();
        hasher.input(seed);
        inner[header_len..].copy_from_slice(hasher.result().as_ref());
        PeerId { inner }
    }

    /// Return raw bytes representation of this peer id
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Consume self, return raw bytes representation of this peer id
    pub fn into_bytes(self) -> Vec<u8> {
        self.inner
    }

    /// Returns a base-58 encoded string of this `PeerId`.
    pub fn to_base58(&self) -> String {
        bs58::encode(self.inner.clone()).into_string()
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PeerId({})", self.to_base58())
    }
}

impl ::std::str::FromStr for PeerId {
    type Err = ();

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = bs58::decode(s).into_vec().map_err(|_| ())?;
        PeerId::from_bytes(bytes)
    }
}
