use blake2b_rs::Blake2bBuilder;
use faster_hex::hex_decode;
use lazy_static::lazy_static;
use rand::Rng;
use secp256k1::{
    key::{PublicKey, SecretKey},
    Message, RecoverableSignature, RecoveryId,
};

mod dns;
mod peer_id;
mod seed_record;

use peer_id::PeerId;
use seed_record::SeedRecord;

lazy_static! {
    pub static ref SECP256K1: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}

// let privkey = SecretKey::from_slice(&privkey_bytes)
//     .expect("create secret key error");
fn main() {
    let seeds = vec!["testnet.local-group.net"];
    let pubkey_str = "0458118103c75b56cddd331c81e685573516e4a1d83ca0b44ba71d9ebbe5d32af3e603fee7116ce53c4775df1bc572acd0e18dd6ab32630dc7bfb13743070fa150";
    let mut pubkey_bytes = [0u8; 65];
    hex_decode(pubkey_str.as_bytes(), &mut pubkey_bytes).expect("hex decode privkey failed");
    let pubkey = PublicKey::from_slice(&pubkey_bytes[..]).expect("Invalid pubke");

    let mut resolver = dns::Resolver::default();
    for seed in seeds {
        for record in resolver.query_txt(seed) {
            // let seed_record = SeedRecord::decode_with_pubkey(&record, &pubkey);
            let result = SeedRecord::decode_with_pubkey(&record, &pubkey);
            println!("seed record: {}\n=> {:#?}\n", record, result);
        }
    }
}

pub struct Generator;

impl Generator {
    pub fn random_keypair() -> (SecretKey, PublicKey) {
        let secret_key = Self::random_secret_key();
        let pubkey = PublicKey::from_secret_key(&*SECP256K1, &secret_key);
        (secret_key, pubkey)
    }

    pub fn random_secret_key() -> SecretKey {
        let mut seed = vec![0; 32];
        let mut rng = rand::thread_rng();
        loop {
            rng.fill(seed.as_mut_slice());
            if let Ok(key) = SecretKey::from_slice(&seed) {
                return key;
            }
        }
    }
}
