use aes::Aes128;
use cmac::{Cmac, Mac};
use hex::encode;
use lazy_static::lazy_static;
use sha2::{Digest, Sha256};

const CMACK_KEY: [u8; 16] = [0_u8; 16];
lazy_static! {
    static ref DATA: Vec<u8> = vec![0_u8; 4096];
}
fn test_cmac128() -> Vec<u8> {
    let mut mac = Cmac::<Aes128>::new_from_slice(&CMACK_KEY[..]).unwrap();
    mac.update(DATA.as_slice());
    let result = mac.finalize();
    let tag = result.into_bytes();

    println!("cmac hex encoded: {}", encode(tag));
    println!("cmac u8 bytes: {:?}", tag);
    tag.to_vec()
}

fn test_sha256() -> Vec<u8> {
    let cmac = test_cmac128();
    debug_assert!(
        cmac.len() == 16,
        "expected the cmac tag len to be 16 bytes, but it was {} bytes",
        cmac.len()
    );
    let mut hasher = Sha256::new();
    hasher.update(cmac.as_slice());
    let result = hasher.finalize();
    println!("single sha hex encoded: {}", encode(result));
    println!("single sha u8 bytes: {:?}", result);
    result.to_vec()

    // let mut hasher = Sha256::new();
    // let mut joined_mac = cmac.clone();
    // joined_mac.extend(cmac);
    // hasher.update(joined_mac.as_slice());
    // let result = hasher.finalize();
    // println!("joined sha hex encoded: {}", encode(result));
    // println!("joined sha u8 bytes: {:?}", result);
    //
    // let joined = result.to_vec();
    // joined
}

fn test_double_sha256() -> Vec<u8> {
    let single_sha = test_sha256();
    let mut hasher = Sha256::new();

    let mut joined_sha = single_sha.clone();
    joined_sha.extend(single_sha);
    hasher.update(joined_sha.as_slice());
    let result = hasher.finalize();
    println!("double sha hex encoded: {}", encode(result));
    println!("double sha u8 bytes: {:?}", result);
    result.to_vec()
}

fn main() {
    test_double_sha256();
}
