// AES Cipher Functionality
// Devin Bidstrup 6/25/24

mod aes128_const {
  pub const KEYLEN: usize = 16; // Key Length in Bytes
  pub const NR: usize = 10; // Number of rounds of the AES Cipher
  pub const NK: usize = KEYLEN / 4; // Size of round key in 32-bit words
}

mod aes192_const {
  pub const KEYLEN: usize = 24;
  pub const NR: usize = 12;
  pub const NK: usize = KEYLEN / 4;
}

mod aes256_const {
  pub const KEYLEN: usize = 32;
  pub const NR: usize = 14;
  pub const NK: usize = KEYLEN / 4;
}

pub mod aes {
  #[cfg(AES_KEYLEN = "128")]
  use crate::aes::aes128_const::*;
  #[cfg(AES_KEYLEN = "192")]
  use crate::aes::aes192_const::*;
  #[cfg(AES_KEYLEN = "256")]
  use crate::aes::aes256_const::*;

  // --------- defs ---------
  const WORDLEN: usize = 4; // Size of a word in bytes
  const BLOCKLEN: usize = 16; // Block length in bytes - AES is 128b block only
  const NB: usize = BLOCKLEN / WORDLEN; // Block length in 32 bit words

  // --------- typedefs ---------
  // Block size words
  type Block = [u8; BLOCKLEN];
  type Word = [u8; WORDLEN];

  // ------------------------------------------ AES Top ------------------------------------------
  // Takes in key, dervies round keys, and then either decrypts or encrypts
  pub fn aes(key: [u8; KEYLEN], data: &mut Block, is_encrypt: bool) {
    // Generate round keys
    let mut rkeys: [Word; 4 * (NR + 1)] = [[0; WORDLEN]; 4 * (NR + 1)];
    key_expansion(key, &mut rkeys);

    // Perform encrypt / decrypt
    if is_encrypt {
      cipher(data, rkeys);
    } else {
      inv_cipher(data, rkeys);
    }
  }

  // ------------------------------------------ Key Expansion ------------------------------------------
  // Key is expanded using the AES key schedule into round+1 keys
  // See FIPS PUB 197 Section 5.2
  fn key_expansion(key: [u8; KEYLEN], rkeys: &mut [Word; 4 * (NR + 1)]) {
    // Round constant, left fixed though could be computed
    const RCON: [Word; 10] = [
      [0x01, 0x00, 0x00, 0x00],
      [0x02, 0x00, 0x00, 0x00],
      [0x04, 0x00, 0x00, 0x00],
      [0x08, 0x00, 0x00, 0x00],
      [0x10, 0x00, 0x00, 0x00],
      [0x20, 0x00, 0x00, 0x00],
      [0x40, 0x00, 0x00, 0x00],
      [0x80, 0x00, 0x00, 0x00],
      [0x1B, 0x00, 0x00, 0x00],
      [0x36, 0x00, 0x00, 0x00],
    ];

    // First Nk words are generated from the key itself
    for word_idx in 0..NK {
      for byte_idx in 0..WORDLEN {
        rkeys[word_idx][byte_idx] = key[(word_idx * WORDLEN) + byte_idx];
      }
    }

    // Every subsequent word w[i] is generated recursively from the
    // preceding word, w[i−1], and the word Nk positions earlier, w[i−Nk] as follows
    // • If i is a multiple of Nk, then w[i] = w[i−Nk] ⊕ subWord(rotWord(w[i−1])) ⊕ Rcon[i/Nk].
    // • For AES-256, if i + 4 is a multiple of 8, then w[i] = w[i−Nk] ⊕ subWord(w[i−1]).
    // • For all other cases, w[i] = w[i−Nk] ⊕ w[i−1].
    let mut sub_rot_word: Word = [0; WORDLEN];
    for word_idx in NK..(4 * (NR + 1)) {
      for byte_idx in 0..WORDLEN {
        sub_rot_word[byte_idx] = rkeys[word_idx - 1][byte_idx];
      }
      if word_idx % NK == 0 {
        rot_word(&mut sub_rot_word);
        sub_word(&mut sub_rot_word);
        for byte_idx in 0..WORDLEN {
          sub_rot_word[byte_idx] = sub_rot_word[byte_idx] ^ RCON[(word_idx / NK) - 1][byte_idx];
        }
      } else if (NK > 6) && (word_idx % NK == 4) {
        sub_word(&mut sub_rot_word);
      }
      for byte_idx in 0..WORDLEN {
        rkeys[word_idx][byte_idx] = (rkeys[word_idx - NK][byte_idx]) ^ (sub_rot_word[byte_idx]);
      }
    }
  }

  // ROTWORD for key expansion
  // [a0, a1, a2, a3] --> [a1, a2, a3, a0]
  fn rot_word(word_in: &mut Word) {
    let temp_byte: u8 = word_in[0];
    for byte_idx in 0..WORDLEN - 1 {
      word_in[byte_idx] = word_in[byte_idx + 1];
    }
    word_in[WORDLEN - 1] = temp_byte;
    return;
  }

  // SUBWORD for key expansion
  // Takes the SBox of all of the elements of the word
  fn sub_word(word_in: &mut Word) {
    for byte_idx in 0..WORDLEN {
      word_in[byte_idx] = sbox(word_in[byte_idx]);
    }
    return;
  }

  //
  // ------------------------------------------ Cipher ------------------------------------------
  // Forward Cipher (Encryption)
  // Takes in initial state and round keys... outputs final state by ref.
  fn cipher(state: &mut Block, rkeys: [Word; WORDLEN * (NR + 1)]) {
    // Setup four word variable to handle round key
    let mut round_key: [Word; NB] = [[0; WORDLEN]; NB];
    for word_idx in 0..NB {
      for byte_idx in 0..WORDLEN {
        round_key[word_idx][byte_idx] = rkeys[word_idx][byte_idx];
      }
    }

    add_round_key(state, round_key);
    for round_idx in 1..NR {
      sub_bytes(state);
      shift_rows(state);
      mix_columns(state);
      for word_idx in 0..NB {
        for byte_idx in 0..WORDLEN {
          round_key[word_idx][byte_idx] = rkeys[(WORDLEN * round_idx) + word_idx][byte_idx];
        }
      }
      add_round_key(state, round_key);
    }
    sub_bytes(state);
    shift_rows(state);
    for word_idx in 0..NB {
      for byte_idx in 0..WORDLEN {
        round_key[word_idx][byte_idx] = rkeys[(WORDLEN * NR) + word_idx][byte_idx];
      }
    }
    add_round_key(state, round_key);
  }

  // SubBytes()
  // Equivalent to an SBox lookup of every byte in the state
  fn sub_bytes(state: &mut Block) {
    for byte_idx in 0..BLOCKLEN {
      state[byte_idx] = sbox(state[byte_idx]);
    }
  }

  // ShiftRows()
  // Bytes in the last three rows of the state are cyclically shifted
  // [00 01 02 03] => [00 01 02 03]
  // [04 05 06 07] => [05 06 07 04]
  // [08 09 10 11] => [10 11 08 09]
  // [12 13 14 15] => [15 12 13 14]
  // or equivalently...
  // [00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15] =>
  // [00 05 10 15 01 06 11 12 02 07 08 13 03 04 09 14]
  fn shift_rows(state: &mut Block) {
    let mut temp_byte: u8;
    for row in 1..NB {
      // Shift start to end once in row 1, twice in row 2, and thrice in row 3
      for _ in 0..row {
        temp_byte = state[row];
        for col in 0..WORDLEN - 1 {
          state[row + (col * WORDLEN)] = state[row + ((col + 1) * WORDLEN)];
        }
        state[row + ((WORDLEN - 1) * WORDLEN)] = temp_byte;
      }
    }
  }

  // MixColumns()
  // Multiplies each of the columns of the state by a fixed matrix
  // [s'_0c] = [02 03 01 01] [s_0c]
  // [s'_1c] = [01 02 03 01] [s_1c]
  // [s'_2c] = [01 01 02 03] [s_2c]
  // [s'_3c] = [03 01 01 02] [s_3c]
  // This is Galois Field Matrix Multiplication, so the result is non-obvious.
  fn mix_columns(state: &mut Block) {
    for col in 0..WORDLEN {
      let mut temp_col: Word = [0; WORDLEN];
      for row in 0..NB {
        temp_col[row] = state[row + (col * WORDLEN)];
      }
      state[(col * WORDLEN) + 0] =
        gf_mult(2, temp_col[0]) ^ gf_mult(3, temp_col[1]) ^ temp_col[2] ^ temp_col[3];
      state[(col * WORDLEN) + 1] =
        temp_col[0] ^ gf_mult(2, temp_col[1]) ^ gf_mult(3, temp_col[2]) ^ temp_col[3];
      state[(col * WORDLEN) + 2] =
        temp_col[0] ^ temp_col[1] ^ gf_mult(2, temp_col[2]) ^ gf_mult(3, temp_col[3]);
      state[(col * WORDLEN) + 3] =
        gf_mult(3, temp_col[0]) ^ temp_col[1] ^ temp_col[2] ^ gf_mult(2, temp_col[3]);
    }
  }

  // AddRoundKey()
  // A Round Key is applied to the state by applying a bitwise XOR operation.
  // Each round key consists of four words, each of which is applied to a column of the state as follows:
  // [s'_0c, s'_1c, s'_2c, s'_3c] = [s_0c, s_1c, s_2c, s_3c] ⊕ [w_(4*round+c)]
  fn add_round_key(state: &mut Block, round_key: [Word; NB]) {
    for byte_idx in 0..BLOCKLEN {
      state[byte_idx] = gf_add(
        state[byte_idx],
        round_key[byte_idx / WORDLEN][byte_idx % WORDLEN],
      );
    }
  }
  //
  // ------------------------------------------ Inverse Cipher ------------------------------------------
  // inverse Cipher (Decryption)
  // Takes in initial state and round keys... outputs final state by ref.
  fn inv_cipher(state: &mut Block, rkeys: [Word; 4 * (NR + 1)]) {
    // Setup four word variable to handle round key
    let mut round_key: [Word; NB] = [[0; WORDLEN]; NB];
    for word_idx in 0..NB {
      for byte_idx in 0..WORDLEN {
        round_key[word_idx][byte_idx] = rkeys[(4 * NR) + word_idx][byte_idx];
      }
    }

    add_round_key(state, round_key);
    for round_idx in (1..NR).rev() {
      inv_shift_rows(state);
      inv_sub_bytes(state);
      for word_idx in 0..NB {
        for byte_idx in 0..WORDLEN {
          round_key[word_idx][byte_idx] = rkeys[(4 * round_idx) + word_idx][byte_idx];
        }
      }
      add_round_key(state, round_key);
      inv_mix_columns(state);
    }
    inv_shift_rows(state);
    inv_sub_bytes(state);
    for word_idx in 0..NB {
      for byte_idx in 0..WORDLEN {
        round_key[word_idx][byte_idx] = rkeys[word_idx][byte_idx];
      }
    }
    add_round_key(state, round_key);
  }

  // InvSubBytes()
  // Equivalent to an invSBox lookup of every byte in the state
  fn inv_sub_bytes(state: &mut Block) {
    for byte_idx in 0..BLOCKLEN {
      state[byte_idx] = inv_sbox(state[byte_idx]);
    }
  }

  // InvShiftRows()
  // Bytes in the last three rows of the state are cyclically shifted in the opposite direction
  // [00 01 02 03] => [00 01 02 03]
  // [04 05 06 07] => [07 04 05 06]
  // [08 09 10 11] => [10 11 08 09]
  // [12 13 14 15] => [13 14 15 12]
  // or equivalently
  // [00 04 08 12 01 05 09 13 02 06 10 14 03 07 11 15] =>
  // [00 07 10 13 01 04 11 14 02 05 08 15 03 06 09 12]
  fn inv_shift_rows(state: &mut Block) {
    let mut temp_byte: u8;
    for row in 1..NB {
      // Shift start to end once in row 1, twice in row 2, and thrice in row 3
      for _ in 0..row {
        temp_byte = state[row + ((WORDLEN - 1) * WORDLEN)];
        for col in (1..WORDLEN).rev() {
          state[row + (col * WORDLEN)] = state[row + ((col - 1) * WORDLEN)];
        }
        state[row] = temp_byte;
      }
    }
  }

  // InvMixColumns()
  // Multiplies each of the columns of the state by a fixed matrix
  // [s'_0c] = [02 03 01 01] [s_0c]
  // [s'_1c] = [01 02 03 01] [s_1c]
  // [s'_2c] = [01 01 02 03] [s_2c]
  // [s'_3c] = [03 01 01 02] [s_3c]
  // This is Galois Field Matrix Multiplication, so the result is non-obvious.
  fn inv_mix_columns(state: &mut Block) {
    for col in 0..WORDLEN {
      let mut temp_col: Word = [0; WORDLEN];
      for row in 0..NB {
        temp_col[row] = state[row + (col * WORDLEN)];
      }
      state[(col * WORDLEN) + 0] = gf_mult(0x0e, temp_col[0])
        ^ gf_mult(0x0b, temp_col[1])
        ^ gf_mult(0x0d, temp_col[2])
        ^ gf_mult(0x09, temp_col[3]);
      state[(col * WORDLEN) + 1] = gf_mult(0x09, temp_col[0])
        ^ gf_mult(0x0e, temp_col[1])
        ^ gf_mult(0x0b, temp_col[2])
        ^ gf_mult(0x0d, temp_col[3]);
      state[(col * WORDLEN) + 2] = gf_mult(0x0d, temp_col[0])
        ^ gf_mult(0x09, temp_col[1])
        ^ gf_mult(0x0e, temp_col[2])
        ^ gf_mult(0x0b, temp_col[3]);
      state[(col * WORDLEN) + 3] = gf_mult(0x0b, temp_col[0])
        ^ gf_mult(0x0d, temp_col[1])
        ^ gf_mult(0x09, temp_col[2])
        ^ gf_mult(0x0e, temp_col[3]);
    }
  }
  // ------------------------------------------ Common Functions ------------------------------------------

  // S-box
  // A substitution table used by AES over many of its constituent functions
  // Derivation from the constants is given in FIPS PUB 197 Section 5.1.1
  const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
  ];
  fn sbox(byte_in: u8) -> u8 {
    return SBOX[usize::from(byte_in)];
  }

  // Inverse S-box
  const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
  ];
  fn inv_sbox(byte_in: u8) -> u8 {
    return INV_SBOX[usize::from(byte_in)];
  }

  // GF Primer
  // The bytes in Galois Fields represent the coefficients of polynomials, for example 01010101b = x^6 + x^4 + x^2 + 1
  // Any operation on a GF, really operates on a polynomial, so special functions are required for the operations

  // GF Addition
  // The coefficients of the elements are added and then reduced modulo 2.
  //  (0+0)mod2 = 0
  //  (0+1)mod2 = 1
  //  (1+0)mod2 = 1
  //  (1+1)mod2 = 0
  // Resulting in the bitwise XOR of the bytes
  fn gf_add(a: u8, b: u8) -> u8 {
    return a ^ b;
  }

  // GF Mult or •
  // The bytes in Galois Fields represent the coefficients of polynomials, for example 01010101b = x^6 + x^4 + x^2 + 1
  // GF Mult of two bytes results in two steps
  // 1) The two polynomials are multiplied as polynomials (multiplication occurs and then coefficients are reduced modulo 2).
  // 2) The resulting polynomial is reduced modulo the following polynomial (x^8 + x^4 + x^3 + x + 1).
  // If one considers the case where the second polynomial, c, is x the following equation can be used to compute the result
  //   xTimes(b) = {{b6,b5,b4,b3,b2,b1,b0,0}                     if b7=0
  //               {{b6,b5,b4,b3,b2,b1,b0,0} ⊕ {0,0,0,1,1,0,1,1} if b7=1
  // Then we can calculate any power of 2^n by repeating that function x times
  // Finally, we can use that to compute the multiplication of any number, by splitting that number into the gf addition
  // of any bit set in the byte
  fn xtimes(b: u8) -> u8 {
    return if (b >> 7) == 0x00 {
      b << 1
    } else {
      (b << 1) ^ (0x1b)
    };
  }
  fn gf_mult(b: u8, c: u8) -> u8 {
    let mut out: u8 = 0x00;

    // Setup mask to extract the bit that we are working on
    let masks: [u8; 8] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80];

    // Setup byte to hold the result as we iterate xTimes
    let mut temp_byte: u8;

    // Loop through every bit in c
    for (c_idx, mask) in masks.iter().enumerate() {
      // Check if that bit is set
      if (c & mask) > 0 {
        // Run xTimes based on the log of the current bit index that we are extracting
        temp_byte = b;
        for _ in 0..c_idx {
          temp_byte = xtimes(temp_byte);
        }

        // GF add the result to the output
        out = gf_add(out, temp_byte);
      }
    }
    return out;
  }

  // ------------------------------------------ Unit Tests ------------------------------------------
  #[test]
  fn test_key_exp() {
    // Setup inputs and expected outputs
    let mut key: [u8; KEYLEN] = [0; KEYLEN];
    let mut exp_round_keys: [u32; 4 * (NR + 1)] = [0; 4 * (NR + 1)];
    #[cfg(AES_KEYLEN = "128")]
    {
      println!("############################\n128 bit AES Key Expansion Test\n############################");
      key = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
      ];
      exp_round_keys = [
        0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c, 0xa0fafe17, 0x88542cb1, 0x23a33939,
        0x2a6c7605, 0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f, 0x3d80477d, 0x4716fe3e,
        0x1e237e44, 0x6d7a883b, 0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00, 0xd4d1c6f8,
        0x7c839d87, 0xcaf2b8bc, 0x11f915bc, 0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd,
        0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f, 0xead27321, 0xb58dbad2, 0x312bf560,
        0x7f8d292f, 0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e, 0xd014f9a8, 0xc9ee2589,
        0xe13f0cc8, 0xb6630ca6,
      ];
    }
    #[cfg(AES_KEYLEN = "192")]
    {
      println!("############################\n192 bit AES Key Expansion Test\n############################");
      key = [
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79,
        0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
      ];
      exp_round_keys = [
        0x8e73b0f7, 0xda0e6452, 0xc810f32b, 0x809079e5, 0x62f8ead2, 0x522c6b7b, 0xfe0c91f7,
        0x2402f5a5, 0xec12068e, 0x6c827f6b, 0x0e7a95b9, 0x5c56fec2, 0x4db7b4bd, 0x69b54118,
        0x85a74796, 0xe92538fd, 0xe75fad44, 0xbb095386, 0x485af057, 0x21efb14f, 0xa448f6d9,
        0x4d6dce24, 0xaa326360, 0x113b30e6, 0xa25e7ed5, 0x83b1cf9a, 0x27f93943, 0x6a94f767,
        0xc0a69407, 0xd19da4e1, 0xec1786eb, 0x6fa64971, 0x485f7032, 0x22cb8755, 0xe26d1352,
        0x33f0b7b3, 0x40beeb28, 0x2f18a259, 0x6747d26b, 0x458c553e, 0xa7e1466c, 0x9411f1df,
        0x821f750a, 0xad07d753, 0xca400538, 0x8fcc5006, 0x282d166a, 0xbc3ce7b5, 0xe98ba06f,
        0x448c773c, 0x8ecc7204, 0x01002202,
      ];
    }
    #[cfg(AES_KEYLEN = "256")]
    {
      println!("############################\n256 bit AES Key Expansion Test\n############################");
      key = [
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77,
        0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14,
        0xdf, 0xf4,
      ];
      exp_round_keys = [
        0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3,
        0x0914dff4, 0x9ba35411, 0x8e6925af, 0xa51a8b5f, 0x2067fcde, 0xa8b09c1a, 0x93d194cd,
        0xbe49846e, 0xb75d5b9a, 0xd59aecb8, 0x5bf3c917, 0xfee94248, 0xde8ebe96, 0xb5a9328a,
        0x2678a647, 0x98312229, 0x2f6c79b3, 0x812c81ad, 0xdadf48ba, 0x24360af2, 0xfab8b464,
        0x98c5bfc9, 0xbebd198e, 0x268c3ba7, 0x09e04214, 0x68007bac, 0xb2df3316, 0x96e939e4,
        0x6c518d80, 0xc814e204, 0x76a9fb8a, 0x5025c02d, 0x59c58239, 0xde136967, 0x6ccc5a71,
        0xfa256395, 0x9674ee15, 0x5886ca5d, 0x2e2f31d7, 0x7e0af1fa, 0x27cf73c3, 0x749c47ab,
        0x18501dda, 0xe2757e4f, 0x7401905a, 0xcafaaae3, 0xe4d59b34, 0x9adf6ace, 0xbd10190d,
        0xfe4890d1, 0xe6188d0b, 0x046df344, 0x706c631e,
      ];
    }

    // Run test
    let mut round_keys: [Word; 4 * (NR + 1)] = [[0; WORDLEN]; 4 * (NR + 1)];
    key_expansion(key, &mut round_keys);

    // Determine result
    println!("---------------------Check key expansion---------------------");
    let mut is_ok: bool = true;
    for round_idx in 0..NR + 1 {
      println!("\n round: {round_idx},");
      println!("ACTUAL,\t\t EXPECTED");
      'for_word: for word_idx in 0..NK {
        if ((4 * round_idx) + word_idx) >= (4 * (NR + 1)) {
          break 'for_word;
        }
        let rk = u32::from_be_bytes(round_keys[(4 * round_idx) + word_idx]);
        let ek = exp_round_keys[(4 * round_idx) + word_idx];
        println!("{rk:>2x}, \t {ek:>2x}");
        if rk != ek {
          is_ok = false;
          println!("\t MISMATCH")
        }
      }
    }
    println!("---------------------\n");

    assert_eq!(is_ok, true);
  }

  #[test]
  fn test_cipher() {
    // Setup inputs and expected outputs
    let mut key: [u8; KEYLEN] = [0; KEYLEN];
    let mut plaintext: [u8; BLOCKLEN] = [0;BLOCKLEN];
    let mut exp_ciphertext: u128 = 0;
    #[cfg(AES_KEYLEN = "128")]
    {
      println!("############################\n128b Key Cipher Test\n############################");
      key = 0x2b7e151628aed2a6abf7158809cf4f3c_u128.to_be_bytes();
      plaintext = 0x3243f6a8885a308d313198a2e0370734_u128.to_be_bytes();
      exp_ciphertext = 0x03925841d_02dc09fb_dc118597_196a0b32_u128;
    }
    #[cfg(AES_KEYLEN = "192")]
    {
      println!("############################\n192b Key Cipher Test\n############################");
      key = [
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79,
        0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b];
      plaintext = 0x6BC1BEE2_2E409F96_E93D7E11_7393172A_u128.to_be_bytes();
      exp_ciphertext = 0xBD334F1D_6E45F25F_F712A214_571FA5CC;
    }
    #[cfg(AES_KEYLEN = "256")]
    {
      println!("############################\n256b Key Cipher Test\n############################");
      key = [
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77,
        0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14,
        0xdf, 0xf4,];
      plaintext = 0x6BC1BEE2_2E409F96_E93D7E11_7393172A_u128.to_be_bytes();
      exp_ciphertext = 0xF3EED1BD_B5D2A03C_064B5A7E_3DB181F8;

    }

    println!("---------------------Before Encryption:---------------------\n");
    println!("plaintext: {:x}", u128::from_be_bytes(plaintext));
    print!("key: ");
    for byte_idx in 0..KEYLEN {
        print!("{:x}", key[byte_idx]);
    }
    print!("\n");
    let mut text: [u8;BLOCKLEN] = plaintext;
    aes(key, &mut text, true);

    println!("---------------------After Encryption:---------------------\n");
    let act_ciphertext = u128::from_be_bytes(text);
    println!("actual ciphertext: {:x}", act_ciphertext);
    println!("expected ciphertext: {:x}\n", exp_ciphertext);
    assert_eq!(exp_ciphertext, act_ciphertext);

    aes(key, &mut text, false);
    println!("---------------------After Encryption:---------------------\n");
    let act_plaintext = u128::from_be_bytes(text);
    let exp_plaintext = u128::from_be_bytes(plaintext);
    println!("actual plaintext: {:x}", act_plaintext);
    println!("expected plaintext: {:x}", exp_plaintext);
    assert_eq!(exp_plaintext, act_plaintext);
  }
} // pub mod aes
