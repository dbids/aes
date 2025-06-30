// AES-ECB
// Devin Bidstrup 6/27/25

// Implement AES Electronic Code Book Mode of Operation
mod aes_ecb {
  use crate::aes::aes::{aes_128, aes_192, aes_256};
  /// These functions apply AES encryption or decryption to each block in the input data
  /// using the specified key. The operation is determined by the `is_encrypt` parameter.
  ///
  /// # Arguments
  /// * `key` - The AES key to use for encryption or decryption. Size is determined by chosen function.
  /// * `data` - An immutable reference to a vector of 128-bit blocks to process.
  /// * `is_encrypt` - A boolean indicating whether to encrypt (true) or decrypt (false).
  ///
  /// # Returns
  /// A vector of processed blocks after applying AES in ECB mode.
  pub fn aes_128_ecb(key: [u8; 16], data: &Vec<u128>, is_encrypt: bool) -> Vec<u128> {
    data
      .iter()
      .map(|&block| aes_128(key, block, is_encrypt))
      .collect()
  }
  pub fn aes_192_ecb(key: [u8; 24], data: &Vec<u128>, is_encrypt: bool) -> Vec<u128> {
    data
      .iter()
      .map(|&block| aes_192(key, block, is_encrypt))
      .collect()
  }
  pub fn aes_256_ecb(key: [u8; 32], data: &Vec<u128>, is_encrypt: bool) -> Vec<u128> {
    data
      .iter()
      .map(|&block| aes_256(key, block, is_encrypt))
      .collect()
  }

  // ------------------------------------------ Unit Tests ------------------------------------------
  #[test]
  // Example from: SP800-38A, Appendix F
  fn test_aes_128_ecb() {
    let key: [u8; 16] = 0x2b7e151628aed2a6abf7158809cf4f3c_u128.to_be_bytes();
    let plaintext: Vec<u128> = vec![
      0x6BC1BEE2_2E409F96_E93D7E11_7393172A,
      0xAE2D8A57_1E03AC9C_9EB76FAC_45AF8E51,
      0x30C81C46_A35CE411_E5FBC119_1A0A52EF,
      0xF69F2445_DF4F9B17_AD2B417B_E66C3710,
    ];
    let exp_ciphertext: Vec<u128> = vec![
      0x3AD77BB4_0D7A3660_A89ECAF3_2466EF97,
      0xF5D3D585_03B9699D_E785895A_96FDBAAF,
      0x43B1CD7F_598ECE23_881B00E3_ED030688,
      0x7B0C785E_27E8AD3F_82232071_04725DD4,
    ];

    println!("---------------------Before Encryption:---------------------\n");
    println!("plaintext: {:x?}", plaintext);
    print!("key: ");
    for byte_idx in 0..16 {
      print!("{:x}", key[byte_idx]);
    }
    print!("\n");

    let act_ciphertext: Vec<u128> = aes_128_ecb(key, &plaintext, true);

    println!("---------------------After Encryption:---------------------\n");
    println!("actual ciphertext: {:x?}", act_ciphertext);
    println!("expected ciphertext: {:x?}\n", exp_ciphertext);
    assert_eq!(exp_ciphertext, act_ciphertext);

    let act_plaintext: Vec<u128> = aes_128_ecb(key, &act_ciphertext, false);

    println!("---------------------After Decryption:---------------------\n");
    println!("actual plaintext: {:x?}", act_plaintext);
    println!("expected plaintext: {:x?}", plaintext);
    assert_eq!(plaintext, act_plaintext);
  }

  #[test]
  // Example from: SP800-38A, Appendix F
  fn test_aes_192_ecb() {
    let key: [u8; 24] = [
      0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79,
      0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
    ];
    let plaintext: Vec<u128> = vec![
      0x6BC1BEE2_2E409F96_E93D7E11_7393172A,
      0xAE2D8A57_1E03AC9C_9EB76FAC_45AF8E51,
      0x30C81C46_A35CE411_E5FBC119_1A0A52EF,
      0xF69F2445_DF4F9B17_AD2B417B_E66C3710,
    ];
    let exp_ciphertext: Vec<u128> = vec![
      0xBD334F1D_6E45F25F_F712A214_571FA5CC,
      0x97410484_6D0AD3AD_7734ECB3_ECEE4EEF,
      0xEF7AFD22_70E2E60A_DCE0BA2F_ACE6444E,
      0x9A4B41BA_738D6C72_FB166916_03C18E0E,
    ];

    println!("---------------------Before Encryption:---------------------\n");
    println!("plaintext: {:x?}", plaintext);
    print!("key: ");
    for byte_idx in 0..24 {
      print!("{:x}", key[byte_idx]);
    }
    print!("\n");

    let act_ciphertext: Vec<u128> = aes_192_ecb(key, &plaintext, true);

    println!("---------------------After Encryption:---------------------\n");
    println!("actual ciphertext: {:x?}", act_ciphertext);
    println!("expected ciphertext: {:x?}\n", exp_ciphertext);
    assert_eq!(exp_ciphertext, act_ciphertext);

    let act_plaintext: Vec<u128> = aes_192_ecb(key, &act_ciphertext, false);

    println!("---------------------After Decryption:---------------------\n");
    println!("actual plaintext: {:x?}", act_plaintext);
    println!("expected plaintext: {:x?}", plaintext);
    assert_eq!(plaintext, act_plaintext);
  }

  #[test]
  // Example from: SP800-38A, Appendix F
  fn test_aes_256_ecb() {
    let key: [u8; 32] = [
      0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77,
      0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14,
      0xdf, 0xf4,
    ];
    let plaintext: Vec<u128> = vec![
      0x6BC1BEE2_2E409F96_E93D7E11_7393172A,
      0xAE2D8A57_1E03AC9C_9EB76FAC_45AF8E51,
      0x30C81C46_A35CE411_E5FBC119_1A0A52EF,
      0xF69F2445_DF4F9B17_AD2B417B_E66C3710,
    ];
    let exp_ciphertext: Vec<u128> = vec![
      0xF3EED1BD_B5D2A03C_064B5A7E_3DB181F8,
      0x591CCB10_D410ED26_DC5BA74A_31362870,
      0xB6ED21B9_9CA6F4F9_F153E7B1_BEAFED1D,
      0x23304B7A_39F9F3FF_067D8D8F_9E24ECC7,
    ];

    println!("---------------------Before Encryption:---------------------\n");
    println!("plaintext: {:x?}", plaintext);
    print!("key: ");
    for byte_idx in 0..32 {
      print!("{:x}", key[byte_idx]);
    }
    print!("\n");

    let act_ciphertext: Vec<u128> = aes_256_ecb(key, &plaintext, true);

    println!("---------------------After Encryption:---------------------\n");
    println!("actual ciphertext: {:x?}", act_ciphertext);
    println!("expected ciphertext: {:x?}\n", exp_ciphertext);
    assert_eq!(exp_ciphertext, act_ciphertext);

    let act_plaintext: Vec<u128> = aes_256_ecb(key, &act_ciphertext, false);

    println!("---------------------After Decryption:---------------------\n");
    println!("actual plaintext: {:x?}", act_plaintext);
    println!("expected plaintext: {:x?}", plaintext);
    assert_eq!(plaintext, act_plaintext);
  }
}
