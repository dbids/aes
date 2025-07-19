//! AES Counter Mode (CTR) Implementation
//! Devin Bidstrup 7/15/25

use crate::aes::{aes_128, aes_192, aes_256};
use std::convert::TryInto;

const BLOCKLEN: usize = 16; // Block length in bytes - AES is 128b block only

/// Encrypts or decrypts data using AES in CTR mode.
///
/// Counter mode (CTR) encrypts a nonce value (the counter) and XORs the result with the plaintext
/// to produce ciphertext, or vice versa. For the last block, which may be a partial block of u bits, the most
/// significant u bits of the last output block are used for the exclusive-OR operation; the remaining
/// block length-u bits of the last output block are discarded.
///
/// # Parameters
/// - `key`: The AES key (128-bit, 192-bit, or 256-bit).
/// - `nonce`: A unique nonce (64-bit).
/// - `data`: The input data to be encrypted or decrypted given as a slice of bytes. Can be of any length.
/// There is no functional difference between encryption and decryption in CTR mode, so no input is given to distinguish the two.
///
/// # Returns
/// The resulting encrypted or decrypted data.
pub fn aes_ctr(key: &[u8], data: &mut [u8], nonce: u64) {
  let mut counter = 0u64;
  for block in data.chunks_mut(BLOCKLEN) {
    // Generate the counter block (nonce + counter)
    let mut counter_block = [0u8; 16];
    counter_block[..8].copy_from_slice(&nonce.to_be_bytes());
    counter_block[8..].copy_from_slice(&counter.to_be_bytes());

    // Encrypt the counter block using the appropriate AES function
    let encrypted_counter_block = match key.len() {
      16 => aes_128(key.try_into().unwrap(), counter_block, true),
      24 => aes_192(key.try_into().unwrap(), counter_block, true),
      32 => aes_256(key.try_into().unwrap(), counter_block, true),
      _ => panic!("Invalid key length. Must be 128, 192, or 256 bits."),
    };

    // XOR the encrypted counter block with the data block to form the ciphertext/plaintext
    block.iter_mut().enumerate().for_each(|(i, byte)| {
      *byte ^= encrypted_counter_block[i];
    });

    // Increment the counter for the next block
    counter += 1;
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_aes_ctr_encrypt_decrypt() {}
}
