use super::mnemonic::{Mnemonic, U11};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct Entropy(Vec<u8>);

impl Entropy {

    pub fn gen(bytes: usize) -> Self {
        let vec: Vec<u8> = (0..bytes).map(|_| { rand::random::<u8>() }).collect();
        Self(vec)
    }

    pub fn checksum(&self) -> u8 {
        let length = self.0.len() * 8 / 32 as usize;
        let mut hash = Sha256::new();
        hash.input(&self.0);
        hash.result()[0] & (0xf0u8 | (0xf0u8 >> (length - 4)))
    }

    pub fn to_mnemonic(&self) -> Mnemonic {
        let mut payload = Vec::<u8>::with_capacity(self.0.len() + 1);
        payload.extend_from_slice(&self.0);
        payload.push(self.checksum());
        let mut u11s = vec![0u16; payload.len() * 8 / 11];
        for i in 0..u11s.len() {
            let bucket = (i * 11 / 8) as usize;
            let offset = (i * 11 % 8) as usize;
            if offset <= 5 {
                u11s[i] = (((payload[bucket] as u16) << (3 + offset))
                    | ((payload[bucket + 1] as u16) >> (5 - offset)))
                    & 0x07ffu16;
            } else {
                u11s[i] = (((payload[bucket] as u16) << (3 + offset))
                    | ((payload[bucket + 1] as u16) << (offset - 5))
                    | (payload[bucket + 2] >> (13 - offset)) as u16)
                    & 0x07ffu16;
            }
        }
        Mnemonic::new(u11s)
    }

    pub fn from_mnemonic(memo: &Mnemonic) -> Result<Entropy, &'static str> {
        let mut temp = Vec::<U11>::with_capacity(memo.0.len() * 11 / 16 + 1);
        for (idx, v) in memo.0.iter().enumerate() {
            let bucket = (idx * 11 / 16) as usize;
            let offset = (idx * 11 % 16) as usize;
            if bucket == temp.len() {
                temp.push(0u16);
            }
            if offset <= 5 {
                temp[bucket] = temp[bucket] | (v << (5 - offset));
            } else {
                temp[bucket] = temp[bucket] | (v >> (offset - 5));
                temp.push(v << (21 - offset));
            }
        }
        // TODO is transmute ok?
        let mut r = Vec::<u8>::with_capacity(temp.len() * 2);
        for t in temp {
            r.push(((t & 0xff00u16) >> 8) as u8);
            r.push((t & 0x00ffu16) as u8);
        }
        r.pop();
        let checksum = r.pop().expect("Illegal mnemonic phrase");
        let entropy = Entropy(r);
        if entropy.checksum() == checksum {
            Ok(entropy)
        } else {
            println!("checksum: {:x}", entropy.checksum());
            println!("phrase: {:x}", checksum);
            Err("Illegal mnemonic phrase, checksum")
        }
    }
}

#[test]
pub fn test() {
    let phrase = "fat wing illegal verb night skull shine still retreat devote chat meat";
    let memo = Mnemonic::from_phrase(phrase).expect("");
    let entropy = Entropy::from_mnemonic(&memo).expect("");
    assert_eq!(
        vec![
            0x53u8, 0x7f, 0x75, 0xc4, 0x79, 0x49, 0x59, 0x95, 0xb1, 0x7e, 0xae, 0xb8, 0x07, 0x98,
            0x9b, 0x45
        ],
        entropy.0
    );
    let mnemonic = entropy.to_mnemonic();
    assert_eq!(entropy.to_mnemonic().0, mnemonic.0);
}
