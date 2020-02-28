use secp256k1::key::{SecretKey, PublicKey};
use secp256k1::{Secp256k1, Message};
use base58::ToBase58;
use sha2::Digest as sha2digest;
use ripemd160::Digest as ripemd160digest;

pub fn new_key(seed256: &[u8]) -> (SecretKey, PublicKey, String) {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&seed256).expect("Illegal seed");
    let pk = PublicKey::from_secret_key(&secp, &sk);
    let r = sha2::Sha256::digest(&pk.serialize());
    let r = ripemd160::Ripemd160::digest(&r);
    let r = [&[0u8], &r[..]].concat();
    let checksum = sha2::Sha256::digest(&sha2::Sha256::digest(&r));
    let mut payload = Vec::<u8>::with_capacity(25);
    payload.extend_from_slice(&r);
    payload.extend_from_slice(&checksum[0..=3]);
    (sk, pk, payload.to_base58())
}

mod test {
    use hex::{decode, decode_to_slice};
    use secp256k1::key::{SecretKey, PublicKey};

    #[test]
    pub fn test() {
        let seed = decode("60cf347dbc59d31c1358c8e5cf5e45b822ab85b79cb32a9f3d98184779a9efc2").expect("");
        let (sk, pk, addr) = super::new_key(&seed);
        let mut pk0 = [0u8; 33];
        decode_to_slice("031e7bcc70c72770dbb72fea022e8a6d07f814d2ebe4de9ae3f7af75bf706902a7", &mut pk0 as &mut [u8]).expect("");
        let pk1 = pk.serialize();
        assert_eq!(pk0[1..33], pk1[1..33]);
        assert_eq!("17JsmEygbbEUEpvt4PFtYaTeSqfb9ki1F1", addr);
    }
}
