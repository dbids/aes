//! AES Cipher Block Chaining (CBC) Mode of Operation
//  Devin Bidstrup 6/27/25

use crate::aes::{aes_128, aes_192, aes_256};

/// This function applies AES-128-CBC encryption or decryption to each block in the input data
/// using the specified key. The operation is determined by the `is_encrypt` parameter.
///
/// # Arguments
/// * `key` - The AES key to use for encryption or decryption. Given as a fixed-size(16B) array of bytes.
/// * `data` - An immutable reference to a vector of 128-bit blocks to process.
/// * `iv` - The initialization vector (IV) used for the first block in CBC mode.
/// * `is_encrypt` - A boolean indicating whether to encrypt (true) or decrypt (false).
///
/// # Returns
/// A vector of processed blocks after applying AES in CBC mode.
pub fn aes_128_cbc(key: [u8; 16], data: &Vec<u128>, iv: u128, is_encrypt: bool) -> Vec<u128> {
  let mut out = data.clone();
  for (b_idx, block) in data.iter().enumerate() {
    if is_encrypt {
      if b_idx == 0 {
        out[b_idx] = aes_128(key, *block ^ iv, true);
      } else {
        out[b_idx] = aes_128(key, *block ^ out[b_idx - 1], true);
      }
    } else {
      if b_idx == 0 {
        out[b_idx] = aes_128(key, *block, false) ^ iv;
      } else {
        out[b_idx] = aes_128(key, *block, false) ^ data[b_idx - 1];
      }
    }
  }
  return out;
}

/// This function applies AES-192-CBC encryption or decryption to each block in the input data
/// using the specified key. The operation is determined by the `is_encrypt` parameter.
///
/// # Arguments
/// * `key` - The AES key to use for encryption or decryption. Given as a fixed-size(24B) array of bytes.
/// * `data` - An immutable reference to a vector of 128-bit blocks to process.
/// * `iv` - The initialization vector (IV) used for the first block in CBC mode.
/// * `is_encrypt` - A boolean indicating whether to encrypt (true) or decrypt (false).
///
/// # Returns
/// A vector of processed blocks after applying AES in CBC mode.
pub fn aes_192_cbc(key: [u8; 24], data: &Vec<u128>, iv: u128, is_encrypt: bool) -> Vec<u128> {
  let mut out = data.clone();
  for (b_idx, block) in data.iter().enumerate() {
    if is_encrypt {
      if b_idx == 0 {
        out[b_idx] = aes_192(key, *block ^ iv, true);
      } else {
        out[b_idx] = aes_192(key, *block ^ out[b_idx - 1], true);
      }
    } else {
      if b_idx == 0 {
        out[b_idx] = aes_192(key, *block, false) ^ iv;
      } else {
        out[b_idx] = aes_192(key, *block, false) ^ data[b_idx - 1];
      }
    }
  }
  return out;
}

/// This function applies AES-256-CBC encryption or decryption to each block in the input data
/// using the specified key. The operation is determined by the `is_encrypt` parameter.
///
/// # Arguments
/// * `key` - The AES key to use for encryption or decryption. Given as a fixed-size(32B) array of bytes.
/// * `data` - An immutable reference to a vector of 128-bit blocks to process.
/// * `iv` - The initialization vector (IV) used for the first block in CBC mode.
/// * `is_encrypt` - A boolean indicating whether to encrypt (true) or decrypt (false).
///
/// # Returns
/// A vector of processed blocks after applying AES in CBC mode.
pub fn aes_256_cbc(key: [u8; 32], data: &Vec<u128>, iv: u128, is_encrypt: bool) -> Vec<u128> {
  let mut out = data.clone();
  for (b_idx, block) in data.iter().enumerate() {
    if is_encrypt {
      if b_idx == 0 {
        out[b_idx] = aes_256(key, *block ^ iv, true);
      } else {
        out[b_idx] = aes_256(key, *block ^ out[b_idx - 1], true);
      }
    } else {
      if b_idx == 0 {
        out[b_idx] = aes_256(key, *block, false) ^ iv;
      } else {
        out[b_idx] = aes_256(key, *block, false) ^ data[b_idx - 1];
      }
    }
  }
  return out;
}

// ------------------------------------------ Unit Tests ------------------------------------------
#[test]
/// Example from: SP800-38A, Appendix F
fn test_aes_128_cbc() {
  let key: [u8; 16] = 0x2b7e151628aed2a6abf7158809cf4f3c_u128.to_be_bytes();
  let iv: u128 = 0x00010203_04050607_08090a0b_0c0d0e0f;
  let plaintext: Vec<u128> = vec![
    0x6BC1BEE2_2E409F96_E93D7E11_7393172A,
    0xAE2D8A57_1E03AC9C_9EB76FAC_45AF8E51,
    0x30C81C46_A35CE411_E5FBC119_1A0A52EF,
    0xF69F2445_DF4F9B17_AD2B417B_E66C3710,
  ];
  let exp_ciphertext: Vec<u128> = vec![
    0x7649abac8119b246cee98e9b12e9197d,
    0x5086cb9b507219ee95db113a917678b2,
    0x73bed6b8e3c1743b7116e69e22229516,
    0x3ff1caa1681fac09120eca307586e1a7,
  ];

  println!("---------------------Before Encryption:---------------------\n");
  println!("plaintext: {:x?}", plaintext);
  print!("key: ");
  for byte_idx in 0..16 {
    print!("{:x}", key[byte_idx]);
  }
  print!("\n");

  let act_ciphertext: Vec<u128> = aes_128_cbc(key, &plaintext, iv, true);

  println!("---------------------After Encryption:---------------------\n");
  println!("actual ciphertext: {:x?}", act_ciphertext);
  println!("expected ciphertext: {:x?}\n", exp_ciphertext);
  assert_eq!(exp_ciphertext, act_ciphertext);

  let act_plaintext: Vec<u128> = aes_128_cbc(key, &act_ciphertext, iv, false);

  println!("---------------------After Decryption:---------------------\n");
  println!("actual plaintext: {:x?}", act_plaintext);
  println!("expected plaintext: {:x?}", plaintext);
  assert_eq!(plaintext, act_plaintext);
}

#[test]
fn test_aes_192_cbc() {
  let key: [u8; 24] = [
    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
  ];
  let iv: u128 = 0x00010203_04050607_08090a0b_0c0d0e0f;
  let plaintext: Vec<u128> = vec![
    0x6bc1bee2_2e409f96_e93d7e11_7393172a,
    0xae2d8a57_1e03ac9c_9eb76fac_45af8e51,
    0x30c81c46_a35ce411_e5fbc119_1a0a52ef,
    0xf69f2445_df4f9b17_ad2b417b_e66c3710,
  ];
  let exp_ciphertext: Vec<u128> = vec![
    0x4f021db243bc633d7178183a9fa071e8,
    0xb4d9ada9ad7dedf4e5e738763f69145a,
    0x571b242012fb7ae07fa9baac3df102e0,
    0x08b0e27988598881d920a9e64f5615cd,
  ];

  println!("---------------------Before Encryption:---------------------\n");
  println!("plaintext: {:x?}", plaintext);
  print!("key: ");
  for byte_idx in 0..24 {
    print!("{:x}", key[byte_idx]);
  }
  print!("\n");

  let act_ciphertext: Vec<u128> = aes_192_cbc(key, &plaintext, iv, true);

  println!("---------------------After Encryption:---------------------\n");
  println!("actual ciphertext: {:x?}", act_ciphertext);
  println!("expected ciphertext: {:x?}\n", exp_ciphertext);
  assert_eq!(exp_ciphertext, act_ciphertext);

  let act_plaintext: Vec<u128> = aes_192_cbc(key, &act_ciphertext, iv, false);

  println!("---------------------After Decryption:---------------------\n");
  println!("actual plaintext: {:x?}", act_plaintext);
  println!("expected plaintext: {:x?}", plaintext);
  assert_eq!(plaintext, act_plaintext);
}

#[test]
fn test_aes_256_cbc() {
  let key: [u8; 32] = [
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
  ];
  let iv: u128 = 0x00010203_04050607_08090a0b_0c0d0e0f;
  let plaintext: Vec<u128> = vec![
    0x6bc1bee2_2e409f96_e93d7e11_7393172a,
    0xae2d8a57_1e03ac9c_9eb76fac_45af8e51,
    0x30c81c46_a35ce411_e5fbc119_1a0a52ef,
    0xf69f2445_df4f9b17_ad2b417b_e66c3710,
  ];
  let exp_ciphertext: Vec<u128> = vec![
    0xf58c4c04d6e5f1ba779eabfb5f7bfbd6,
    0x9cfc4e967edb808d679f777bc6702c7d,
    0x39f23369a9d9bacfa530e26304231461,
    0xb2eb05e2c39be9fcda6c19078c6a9d1b,
  ];

  println!("---------------------Before Encryption:---------------------\n");
  println!("plaintext: {:x?}", plaintext);
  print!("key: ");
  for byte_idx in 0..24 {
    print!("{:x}", key[byte_idx]);
  }
  print!("\n");

  let act_ciphertext: Vec<u128> = aes_256_cbc(key, &plaintext, iv, true);

  println!("---------------------After Encryption:---------------------\n");
  println!("actual ciphertext: {:x?}", act_ciphertext);
  println!("expected ciphertext: {:x?}\n", exp_ciphertext);
  assert_eq!(exp_ciphertext, act_ciphertext);

  let act_plaintext: Vec<u128> = aes_256_cbc(key, &act_ciphertext, iv, false);

  println!("---------------------After Decryption:---------------------\n");
  println!("actual plaintext: {:x?}", act_plaintext);
  println!("expected plaintext: {:x?}", plaintext);
  assert_eq!(plaintext, act_plaintext);
}
