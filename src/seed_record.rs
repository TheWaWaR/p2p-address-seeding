use std::net::IpAddr;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use faster_hex::{hex_decode, hex_string};
use secp256k1::{
    key::{PublicKey, SecretKey},
    Message, RecoverableSignature, RecoveryId,
};

use crate::{PeerId, SECP256K1};

const SEP: char = ';';

// ip          : max   39 bytes (2001:0dc5:72a3:0000:0000:802e:3370:73E4)
// port        : max   5 bytes (65535)
// peer_id     : max   (32 + 3) * 2 * 0.8 = 56 bytes (base58)
// valid_until : max   11 bytes (31536000000, 1000 year)
// signature   : max   65 * 2 * 0.8 = 104 bytes (base58)
// sep         : exact 4 bytes
// total       : max   39 + 5 + 56 + 11 + 104 + 4 = 224 bytes
// txt limit   : 255 bytes (enough)
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SeedRecord {
    ip: IpAddr,
    port: u16,
    peer_id: Option<PeerId>,
    // Future utc timestamp
    valid_until: u64,
    pubkey: PublicKey,
}

impl SeedRecord {
    pub fn new(
        ip: IpAddr,
        port: u16,
        peer_id: Option<PeerId>,
        valid_until: u64,
        pubkey: PublicKey,
    ) -> SeedRecord {
        SeedRecord {
            ip,
            port,
            peer_id,
            valid_until,
            pubkey,
        }
    }

    pub fn check(&self) -> Result<(), SeedRecordError> {
        if !is_reachable(self.ip) {
            return Err(SeedRecordError::InvalidIp(self.ip));
        }

        if self.port == 0 {
            return Err(SeedRecordError::InvalidPort(self.port));
        }

        if SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs()
            > self.valid_until
        {
            return Err(SeedRecordError::SeedTimeout);
        }
        Ok(())
    }

    // Design for human readable
    pub fn encode(&self, privkey: &SecretKey) -> Result<String, SeedRecordError> {
        if PublicKey::from_secret_key(&SECP256K1, privkey) != self.pubkey {
            return Err(SeedRecordError::KeyNotMatch);
        }

        let data = Self::data_to_sign(self.ip, self.port, self.peer_id.as_ref(), self.valid_until);
        let hash = sha3_256(&data);
        println!("data: {}, hash: {:?}", data, hash);
        let message = Message::from_slice(&hash).expect("create message error");

        let signature = SECP256K1.sign_recoverable(&message, privkey);
        let (recid, signed_data) = signature.serialize_compact();
        let mut sig = [0u8; 65];
        sig[0..64].copy_from_slice(&signed_data[0..64]);
        sig[64] = recid.to_i32() as u8;
        let signature_string = bs58::encode(&sig[..]).into_string();
        Ok(vec![data, signature_string].join(&SEP.to_string()))
    }

    pub fn decode(record: &str) -> Result<SeedRecord, SeedRecordError> {
        if record.split(SEP).count() != 5 {
            return Err(SeedRecordError::InvalidRecord);
        }

        let mut parts = record.split(SEP);
        let ip: IpAddr = parts
            .next()
            .unwrap()
            .parse()
            .map_err(|_| SeedRecordError::InvalidRecord)?;
        let port: u16 = parts
            .next()
            .unwrap()
            .parse()
            .map_err(|_| SeedRecordError::InvalidRecord)?;
        let peer_id_str = parts.next().unwrap();
        let peer_id = if peer_id_str.len() > 0 {
            Some(PeerId::from_str(peer_id_str).map_err(|_| SeedRecordError::InvalidRecord)?)
        } else {
            None
        };
        let valid_until: u64 = parts
            .next()
            .unwrap()
            .parse()
            .map_err(|_| SeedRecordError::InvalidRecord)?;
        let sig: Vec<u8> = bs58::decode(parts.next().unwrap())
            .into_vec()
            .map_err(|_| SeedRecordError::InvalidRecord)?;

        if sig.len() != 65 {
            return Err(SeedRecordError::InvalidRecord);
        }

        let recid = RecoveryId::from_i32(i32::from(sig[64]))
            .map_err(|_| SeedRecordError::InvalidSignature)?;
        let signature = RecoverableSignature::from_compact(&sig[0..64], recid)
            .map_err(|_| SeedRecordError::InvalidSignature)?;

        let data = Self::data_to_sign(ip, port, peer_id.as_ref(), valid_until);
        let hash = sha3_256(&data);
        println!("data: {}, hash: {:?}", data, hash);
        let message = Message::from_slice(&hash).expect("create message error");

        if let Ok(pubkey) = SECP256K1.recover(&message, &signature) {
            Ok(SeedRecord {
                ip,
                port,
                peer_id,
                valid_until,
                pubkey,
            })
        } else {
            return Err(SeedRecordError::InvalidSignature);
        }
    }

    pub fn decode_with_pubkey(
        record: &str,
        pubkey: &PublicKey,
    ) -> Result<SeedRecord, SeedRecordError> {
        let seed_record = Self::decode(record)?;
        if &seed_record.pubkey != pubkey {
            Err(SeedRecordError::VerifyFailed)
        } else {
            seed_record.check()?;
            Ok(seed_record)
        }
    }

    pub fn ip(&self) -> IpAddr {
        self.ip
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    pub fn valid_until(&self) -> u64 {
        self.valid_until
    }
    pub fn peer_id(&self) -> Option<&PeerId> {
        self.peer_id.as_ref()
    }
    pub fn pubkey(&self) -> &PublicKey {
        &self.pubkey
    }

    fn data_to_sign(ip: IpAddr, port: u16, peer_id: Option<&PeerId>, valid_until: u64) -> String {
        vec![
            ip.to_string(),
            port.to_string(),
            peer_id
                .map(PeerId::to_base58)
                .unwrap_or_else(|| String::new()),
            valid_until.to_string(),
        ]
        .join(&SEP.to_string())
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum SeedRecordError {
    InvalidRecord,
    InvalidIp(IpAddr),
    InvalidPort(u16),
    InvalidSignature,
    VerifyFailed,
    SeedTimeout,
    // Secret not match the public key
    KeyNotMatch,
}

pub fn sha3_256<T: AsRef<[u8]>>(s: T) -> [u8; 32] {
    tiny_keccak::sha3_256(s.as_ref())
}

/// Check if the ip address is reachable.
/// Copy from std::net::IpAddr::is_global
fn is_reachable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            !ipv4.is_private()
                && !ipv4.is_loopback()
                && !ipv4.is_link_local()
                && !ipv4.is_broadcast()
                && !ipv4.is_documentation()
                && !ipv4.is_unspecified()
        }
        IpAddr::V6(ipv6) => {
            let scope = if ipv6.is_multicast() {
                match ipv6.segments()[0] & 0x000f {
                    1 => Some(false),
                    2 => Some(false),
                    3 => Some(false),
                    4 => Some(false),
                    5 => Some(false),
                    8 => Some(false),
                    14 => Some(true),
                    _ => None,
                }
            } else {
                None
            };
            match scope {
                Some(true) => true,
                None => {
                    !(ipv6.is_multicast()
                      || ipv6.is_loopback()
                      // && !ipv6.is_unicast_link_local()
                      || ((ipv6.segments()[0] & 0xffc0) == 0xfe80)
                      // && !ipv6.is_unicast_site_local()
                      || ((ipv6.segments()[0] & 0xffc0) == 0xfec0)
                      // && !ipv6.is_unique_local()
                      || ((ipv6.segments()[0] & 0xfe00) == 0xfc00)
                      || ipv6.is_unspecified()
                      // && !ipv6.is_documentation()
                      || ((ipv6.segments()[0] == 0x2001) && (ipv6.segments()[1] == 0xdb8)))
                }
                _ => false,
            }
        }
    }
}

mod tests {
    use super::*;
    use crate::Generator;

    fn now_ts() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs()
    }

    #[test]
    fn simple() {
        let ipv4: IpAddr = "153.149.96.217".parse().unwrap();
        let port = 4455;
        let peer_id = Some(PeerId::random());
        // 180 seconds in future
        let valid_until = now_ts() + 180;
        let (priv1, pub1) = Generator::random_keypair();
        let (priv2, pub2) = Generator::random_keypair();
        let record = SeedRecord::new(ipv4, port, peer_id.clone(), valid_until, pub1.clone());
        assert_eq!(record.encode(&priv2), Err(SeedRecordError::KeyNotMatch));
        let record_string = record.encode(&priv1).unwrap();
        println!("txt record: {}", record_string);
        let ret = SeedRecord::decode(record_string.as_str());
        assert!(ret.is_ok());
        let record = ret.unwrap();
        assert!(record.check().is_ok());
        assert!(record.pubkey() != &pub2);

        let ipv6: IpAddr = "2001:0dc5:72a3:0000:0000:802e:3370:73E4".parse().unwrap();
        let record = SeedRecord::new(ipv6, port, peer_id.clone(), valid_until, pub1.clone());
        let record_string = record.encode(&priv1).unwrap();
        println!("txt record: {}", record_string);
    }
}
