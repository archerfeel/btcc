use base58::ToBase58;
use secp256k1::key::{PublicKey, SecretKey};
use secp256k1::Secp256k1;
use sha2::Digest as sha2digest;

pub fn from_seed(seed256: &[u8]) -> (String, String) {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&seed256).expect("Illegal seed");
    let pk = PublicKey::from_secret_key(&secp, &sk);
    (encode_pri_key(&sk), export_address(&pk))
}

fn export_address(pk: &PublicKey) -> String {
    let compressed = pk.serialize();
    let hash160 = ripemd160::Ripemd160::digest(&sha2::Sha256::digest(&compressed));
    let net_version = [&[0u8], &hash160[..]].concat();
    let checksum = sha2::Sha256::digest(&sha2::Sha256::digest(&net_version));
    [&net_version[..], &checksum[0..4]].concat().to_base58()
}

fn encode_pri_key(sk: &SecretKey) -> String {
    let payload = unsafe { std::slice::from_raw_parts(sk.as_ptr(), sk.len()) };
    let net_version = [&[0x80u8], &payload[..], &[0x01u8]].concat();
    let checksum = sha2::Sha256::digest(&sha2::Sha256::digest(&net_version));
    [&net_version[..], &checksum[0..4]].concat().to_base58()
}

#[test]
pub fn test() {
    let seed =
        hex::decode("60cf347dbc59d31c1358c8e5cf5e45b822ab85b79cb32a9f3d98184779a9efc2").expect("");
    let (wif, addr) = from_seed(&seed);
    assert_eq!("KzTtuNKTTUeS186RqeFtQ7WzVYagcT46ojzEhoudUiwwsWtvokhD", wif);
    assert_eq!("17JsmEygbbEUEpvt4PFtYaTeSqfb9ki1F1", addr);
}
