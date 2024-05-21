//! In Module 1, we discussed Block ciphers like AES. Block ciphers have a fixed length input.
//! Real wold data that we wish to encrypt _may_ be exactly the right length, but is probably not.
//! When your data is too short, you can simply pad it up to the correct length.
//! When your data is too long, you have some options.
//!
//! In this exercise, we will explore a few of the common ways that large pieces of data can be
//! broken up and combined in order to encrypt it with a fixed-length block cipher.
//!
//! WARNING: ECB MODE IS NOT SECURE.
//! Seriously, ECB is NOT secure. Don't use it irl. We are implementing it here to understand _why_
//! it is not secure and make the point that the most straight-forward approach isn't always the
//! best, and can sometimes be trivially broken.

use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128,
};
use rand::*;

///We're using AES 128 which has 16-byte (128 bit) blocks.
const BLOCK_SIZE: usize = 16;
const INIT: [u8; BLOCK_SIZE] = [12, 5, 2, 11, 4, 5, 12, 5, 2, 11, 4, 5, 12, 4, 6, 12];
const NONCE_SIZE: usize = 8; // 64 bits

fn main() {
    let data: Vec<u8> = vec![12, 4, 5, 5, 2, 11];
    let data16: Vec<u8> = vec![12, 12, 4, 6, 12, 5, 5, 12, 5, 2, 2, 11, 4, 11, 4, 5];
    let key: [u8; 16] = [12, 5, 2, 11, 5, 4, 5, 0, 12, 4, 6, 12, 5, 2, 11, 4];
    let encrypt = cbc_encrypt(data.clone(), key);
    let encrypt16 = cbc_encrypt(data16.clone(), key);

    println!("CBC encrypted data {:?}", encrypt);
    println!("CBC encrypted data 16 {:?}", encrypt16);
    println!("CBC un-encrypted data {:?}", cbc_decrypt(encrypt, key));
    println!("CBC un-encrypted data 16 {:?}", cbc_decrypt(encrypt16, key));

    let encrypt = ecb_encrypt(data.clone(), key);
    let encrypt16 = ecb_encrypt(data16.clone(), key);
    println!("ECB encrypted data {:?}", encrypt);
    println!("ECB encrypted data 16 {:?}", encrypt16);
    println!("ECB un-encrypted data {:?}", ecb_decrypt(encrypt, key));
    println!("ECB un-encrypted data 16 {:?}", ecb_decrypt(encrypt16, key));

    let ctr_cipher = ctr_encrypt(data, key);
    println!("CTR encrypted data {:?}", ctr_cipher);
    println!("CTR decrypted data {:?}", ctr_decrypt(ctr_cipher, key));

    let ctr_cipher16 = ctr_encrypt(data16, key);
    println!("CTR encrypted data 16 {:?}", ctr_cipher16);
    println!("CTR decrypted data 16 {:?}", ctr_decrypt(ctr_cipher16, key));
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_encrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    // Convert the inputs to the necessary data type
    let mut block = GenericArray::from(data);
    let key = GenericArray::from(*key);

    let cipher = Aes128::new(&key);

    cipher.encrypt_block(&mut block);

    block.into()
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_decrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    // Convert the inputs to the necessary data type
    let mut block = GenericArray::from(data);
    let key = GenericArray::from(*key);

    let cipher = Aes128::new(&key);

    cipher.decrypt_block(&mut block);

    block.into()
}

/// Before we can begin encrypting our raw data, we need it to be a multiple of the
/// block length which is 16 bytes (128 bits) in AES128.
///
/// The padding algorithm here is actually not trivial. The trouble is that if we just
/// naively throw a bunch of zeros on the end, there is no way to know, later, whether
/// those zeros are padding, or part of the message, or some of each.
///
/// The scheme works like this. If the data is not a multiple of the block length,  we
/// compute how many pad bytes we need, and then write that number into the last several bytes.
/// Later we look at the last byte, and remove that number of bytes.
///
/// But if the data _is_ a multiple of the block length, then we have a problem. We don't want
/// to later look at the last byte and remove part of the data. Instead, in this case, we add
/// another entire block containing the block length in each byte. In our case,
/// [16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16]
fn pad(mut data: Vec<u8>) -> Vec<u8> {
    // When twe have a multiple the second term is 0
    let number_pad_bytes = BLOCK_SIZE - data.len() % BLOCK_SIZE;

    for _ in 0..number_pad_bytes {
        data.push(number_pad_bytes as u8);
    }

    data
}

/// Groups the data into BLOCK_SIZE blocks. Assumes the data is already
/// a multiple of the block size. If this is not the case, call `pad` first.
fn group(data: Vec<u8>) -> Vec<[u8; BLOCK_SIZE]> {
    let mut blocks = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let mut block: [u8; BLOCK_SIZE] = Default::default();
        block.copy_from_slice(&data[i..i + BLOCK_SIZE]);
        blocks.push(block);

        i += BLOCK_SIZE;
    }

    blocks
}

/// Does the opposite of the group function
fn un_group(blocks: Vec<[u8; BLOCK_SIZE]>) -> Vec<u8> {
    blocks.iter().fold(Vec::new(), |mut vec, chunk| {
        vec.extend_from_slice(&chunk[..]);
        vec
    })
}

/// Does the opposite of the pad function.
fn un_pad(data: Vec<[u8; BLOCK_SIZE]>) -> Vec<u8> {
    let mut arr = un_group(data);
    let bytes_to_remove = arr[arr.len() - 1] as usize;
    arr.truncate(arr.len() - bytes_to_remove);
    arr
}

/// The first mode we will implement is the Electronic Code Book, or ECB mode.
/// Warning: THIS MODE IS NOT SECURE!!!!
///
/// This is probably the first thing you think of when considering how to encrypt
/// large data. In this mode we simply encrypt each block of data under the same key.
/// One good thing about this mode is that it is parallelizable. But to see why it is
/// insecure look at: https://www.ubiqsecurity.com/wp-content/uploads/2022/02/ECB2.png
fn ecb_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    let blocks = group(pad(plain_text));
    un_group(blocks.iter().map(|bl| aes_encrypt(*bl, &key)).collect())
}

/// Opposite of ecb_encrypt.
fn ecb_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    un_pad(
        group(cipher_text)
            .iter()
            .map(|block| aes_decrypt(*block, &key))
            .collect(),
    )
}

/// The next mode, which you can implement on your own is cipherblock chaining.
/// This mode actually is secure, and it often used in real world applications.
///
/// In this mode, the ciphertext from the first block is XORed with the
/// plaintext of the next block before it is encrypted.
fn cbc_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    // Remember to generate a random initialization vector for the first block.
    let mut data: Vec<u8> = vec![];
    let chunks = group(pad(plain_text));
    let mut to_xor: [u8; BLOCK_SIZE] = INIT;
    chunks.iter().for_each(|ch| {
        let xored = xor(*ch, to_xor);
        let encrypted = aes_encrypt(xored.try_into().unwrap(), &key);
        to_xor = encrypted;
        data.extend_from_slice(&encrypted);
    });
    data
}

fn cbc_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    let chunks: Vec<[u8; BLOCK_SIZE]> = group(cipher_text);
    let mut unencrypted_chunks: Vec<[u8; BLOCK_SIZE]> = vec![];
    let mut to_xor: [u8; BLOCK_SIZE] = INIT;
    chunks.iter().for_each(|ch| {
        let data = aes_decrypt(*ch, &key);
        let xored = xor(data, to_xor);
        unencrypted_chunks.push(xored.try_into().unwrap());
        to_xor = *ch;
    });
    un_pad(unencrypted_chunks)
}

/// Another mode which you can implement on your own is counter mode.
/// This mode is secure as well, and is used in real world applications.
/// It allows parallelized encryption and decryption, as well as random read access when decrypting.
///
/// In this mode, there is an index for each block being encrypted (the "counter"), as well as a random nonce.
/// For a 128-bit cipher, the nonce is 64 bits long.
///
/// For the ith block, the 128-bit value V of `nonce | counter` is constructed, where | denotes
/// concatenation. Then, V is encrypted with the key using ECB mode. Finally, the encrypted V is
/// XOR'd with the plaintext to produce the ciphertext.
///
/// A very clear diagram is present here:
/// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
///
/// Once again, you will need to generate a random nonce which is 64 bits long. This should be
/// inserted as the first block of the ciphertext.
fn ctr_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill(&mut nonce);

    let mut cipher_text = vec![0u8; plain_text.len() + NONCE_SIZE];
    cipher_text[..NONCE_SIZE].copy_from_slice(&nonce);

    for (i, block) in plain_text.chunks(BLOCK_SIZE).enumerate() {
        let counter = (i as u64).to_be_bytes();
        let mut v = [0u8; BLOCK_SIZE];
        v[..NONCE_SIZE].copy_from_slice(&nonce);
        v[NONCE_SIZE..].copy_from_slice(&counter);

        let encrypted_v = ecb_encrypt(v.to_vec(), key);

        let start = NONCE_SIZE + i * BLOCK_SIZE;
        let end = start + block.len();
        cipher_text[start..end].copy_from_slice(&xor(block, &encrypted_v));
    }

    cipher_text
}

fn ctr_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    let nonce = &cipher_text[..NONCE_SIZE];
    let cipher_blocks = &cipher_text[NONCE_SIZE..];

    let mut plain_text = vec![];

    for (i, block) in cipher_blocks.chunks(BLOCK_SIZE).enumerate() {
        let counter = (i as u64).to_be_bytes();
        let mut v = [0u8; BLOCK_SIZE];
        v[..NONCE_SIZE].copy_from_slice(nonce);
        v[NONCE_SIZE..].copy_from_slice(&counter);

        let encrypted_v = aes_encrypt(v, &key);

        plain_text.extend_from_slice(&xor(block, &encrypted_v[..block.len()]));
    }

    plain_text
}

fn xor<T: AsRef<[u8]>, U: AsRef<[u8]>>(a: T, b: U) -> Vec<u8> {
    let a = a.as_ref();
    let b = b.as_ref();
    let mut result = Vec::with_capacity(a.len().max(b.len()));

    for (x, y) in a.iter().zip(b.iter().cycle()) {
        result.push(x ^ y);
    }

    result
}
