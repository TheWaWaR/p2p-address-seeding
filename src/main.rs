use std::error::Error;
use std::fs;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use blake2b_rs::Blake2bBuilder;
use chrono::DateTime;
use clap::{App, Arg, ArgMatches, SubCommand};
use faster_hex::hex_decode;
use lazy_static::lazy_static;
use parity_multiaddr::{Multiaddr, Protocol};
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

fn main() -> Result<(), Box<Error>> {
    let arg_privkey = Arg::with_name("privkey-file")
        .short("p")
        .long("privkey-file")
        .required(true)
        .takes_value(true)
        .help("Private key file path (64 length hex string)");

    let matches = App::new("")
        .subcommand(
            SubCommand::with_name("generate")
                .arg(arg_privkey.clone())
                .arg(
                    Arg::with_name("addr")
                        .short("a")
                        .long("addr")
                        .required(true)
                        .takes_value(true)
                        .help("Target address, format: {ip}:{port} or multiaddr"),
                )
                .arg(
                    Arg::with_name("peer-id")
                        .long("peer-id")
                        .takes_value(true)
                        .help("Peer Id for secure network connection"),
                )
                .arg(
                    Arg::with_name("valid-until")
                        .long("valid-until")
                        .required(true)
                        .takes_value(true)
                        .help("Valid until datetime (RFC3339: '2014-11-28T21:00:09+09:00')"),
                ),
        )
        .subcommand(
            SubCommand::with_name("query")
                .arg(arg_privkey.clone())
                .arg(
                    Arg::with_name("pubkey")
                        .long("pubkey")
                        .takes_value(true)
                        .multiple(true)
                        .help("Public key (128 length hex string)"),
                )
                .arg(
                    Arg::with_name("domain")
                        .short("d")
                        .long("domain")
                        .default_value("crystal-nova.rylai.nervos.org")
                        .required(true)
                        .takes_value(true)
                        .help("The domain for query TXT records"),
                ),
        )
        .get_matches();
    match matches.subcommand() {
        ("generate", Some(sub_matches)) => {
            generate(sub_matches)?;
        }
        ("query", Some(sub_matches)) => {
            query(sub_matches)?;
        }
        _ => {
            eprintln!("Invalid arguments");
        }
    }
    Ok(())
}

fn generate(matches: &ArgMatches) -> Result<(), Box<Error>> {
    let privkey_path = matches.value_of("privkey-file").unwrap();
    let mut privkey_string = String::new();
    let mut file = fs::File::open(privkey_path)?;
    file.read_to_string(&mut privkey_string)?;
    let mut privkey_bytes = [0u8; 32];
    hex_decode(privkey_string.trim().as_bytes(), &mut privkey_bytes)?;
    let privkey = SecretKey::from_slice(&privkey_bytes[..])?;
    let pubkey = PublicKey::from_secret_key(&SECP256K1, &privkey);

    let addr_str = matches.value_of("addr").unwrap();
    let (addr, peer_id) = if let Ok(multiaddr) = Multiaddr::from_str(addr_str) {
        let mut ip: Option<IpAddr> = None;
        let mut port = None;
        let mut peer_id = None;
        for part in multiaddr.iter() {
            match part {
                Protocol::Ip4(value) => {
                    ip = Some(value.into());
                }
                Protocol::Ip6(value) => {
                    ip = Some(value.into());
                }
                Protocol::Tcp(value) => {
                    port = Some(value);
                }
                Protocol::P2p(value) => {
                    peer_id = PeerId::from_bytes(value.into_bytes()).ok();
                }
                _ => {}
            }
        }
        let ip = ip.ok_or("Missing ip field")?;
        let port = port.ok_or("Missing port field")?;
        (SocketAddr::from((ip, port)), peer_id)
    } else {
        let addr = addr_str
            .parse::<SocketAddr>()
            .map_err(|_| "parse socket address failed")?;
        let peer_id_str = matches.value_of("peer-id").unwrap_or("");
        let peer_id = if peer_id_str.is_empty() {
            None
        } else {
            Some(PeerId::from_str(peer_id_str).map_err(|_| "Invalid peer id")?)
        };
        (addr, peer_id)
    };
    let valid_until_str = matches.value_of("valid-until").unwrap();
    let valid_until = DateTime::parse_from_rfc3339(valid_until_str)?.timestamp();
    if valid_until
        < SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs() as i64
    {
        return Err("<valid-until> not a future time".into());
    }

    let seed_record = SeedRecord::new(addr.ip(), addr.port(), peer_id, valid_until as u64, pubkey);
    seed_record.check().map_err(|err| format!("{:?}", err))?;
    let txt_record = seed_record
        .encode(&privkey)
        .map_err(|err| format!("{:?}", err))?;
    println!("[TXT record]:\n{}", txt_record);
    Ok(())
}

fn query(matches: &ArgMatches) -> Result<(), Box<Error>> {
    Ok(())
}

fn check(matches: &ArgMatches) -> Result<(), Box<Error>> {
    Ok(())
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
