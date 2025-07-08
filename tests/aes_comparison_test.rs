#[test]
fn aes_128_comparison_test() {
  use aes::Aes128;
  use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};
  use dbids_aes::aes::aes_128;
  use rand::Rng;

  // Get an RNG:
  let mut rng = rand::rng();

  // Setup key and cipher
  let mut key_128 = [0u8; 16]; // 128-bit key
  rng.fill(&mut key_128);
  let key_128_lib = Array::from(key_128);
  let cipher_128 = Aes128::new(&key_128_lib);

  // Run the test for AES128
  for _i in 0..1000 {
    // Generate plaintext
    let plaintext: u128 = rng.random();

    // Generate ciphertext from AES library
    let mut expected_ciphertext = Array::from(plaintext.to_be_bytes().clone());
    cipher_128.encrypt_block(&mut expected_ciphertext);

    // Generate ciphertext from my AES implementation
    let my_ciphertext = aes_128(key_128, plaintext, true);

    // Check if the ciphertexts match
    let expected_ciphertext = expected_ciphertext.to_vec();
    let expected_ciphertext: [u8; 16] = expected_ciphertext
      .try_into()
      .expect("Expected ciphertext should be 16 bytes long");
    assert_eq!(
      u128::from_be_bytes(expected_ciphertext),
      my_ciphertext,
      "AES-128 encryption failed."
    );

    // Decrypt the ciphertext my AES library
    let my_plaintext = aes_128(key_128, my_ciphertext, false);

    // Check if decryption matches the original plaintext
    assert_eq!(plaintext, my_plaintext, "AES-128 decryption failed.");
  }
}

#[test]
fn aes_192_comparison_test() {
  use aes::Aes192;
  use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};
  use dbids_aes::aes::aes_192;
  use rand::Rng;

  // Get an RNG:
  let mut rng = rand::rng();

  // Setup key and cipher
  let mut key_192 = [0u8; 24]; // 192-bit key
  rng.fill(&mut key_192);
  let key_192_lib = Array::from(key_192);
  let cipher_192 = Aes192::new(&key_192_lib);

  // Run the test for AES-192
  for _i in 0..1000 {
    // Generate plaintext
    let plaintext: u128 = rng.random();

    // Generate ciphertext from AES library
    let mut expected_ciphertext = Array::from(plaintext.to_be_bytes().clone());
    cipher_192.encrypt_block(&mut expected_ciphertext);

    // Generate ciphertext from my AES implementation
    let my_ciphertext = aes_192(key_192, plaintext, true);

    // Check if the ciphertexts match
    let expected_ciphertext = expected_ciphertext.to_vec();
    let expected_ciphertext: [u8; 16] = expected_ciphertext
      .try_into()
      .expect("Expected ciphertext should be 16 bytes long");
    assert_eq!(
      u128::from_be_bytes(expected_ciphertext),
      my_ciphertext,
      "AES-192 encryption failed."
    );

    // Decrypt the ciphertext my AES library
    let my_plaintext = aes_192(key_192, my_ciphertext, false);

    // Check if decryption matches the original plaintext
    assert_eq!(plaintext, my_plaintext, "AES-192 decryption failed.");
  }
}

//Write a comparison test similar to `aes_128_comparison_test` for AES-256
#[test]
fn aes_256_comparison_test() {
  use aes::Aes256;
  use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};
  use dbids_aes::aes::aes_256;
  use rand::Rng;

  // Get an RNG:
  let mut rng = rand::rng();

  // Setup key and cipher
  let mut key_256 = [0u8; 32]; // 256-bit key
  rng.fill(&mut key_256);
  let key_256_lib = Array::from(key_256);
  let cipher_256 = Aes256::new(&key_256_lib);

  // Run the test for AES-256
  for _i in 0..1000 {
    // Generate plaintext
    let plaintext: u128 = rng.random();

    // Generate ciphertext from AES library
    let mut expected_ciphertext = Array::from(plaintext.to_be_bytes().clone());
    cipher_256.encrypt_block(&mut expected_ciphertext);

    // Generate ciphertext from my AES implementation
    let my_ciphertext = aes_256(key_256, plaintext, true);

    // Check if the ciphertexts match
    let expected_ciphertext = expected_ciphertext.to_vec();
    let expected_ciphertext: [u8; 16] = expected_ciphertext
      .try_into()
      .expect("Expected ciphertext should be 16 bytes long");
    assert_eq!(
      u128::from_be_bytes(expected_ciphertext),
      my_ciphertext,
      "AES-256 encryption failed."
    );

    // Decrypt the ciphertext my AES library
    let my_plaintext = aes_256(key_256, my_ciphertext, false);

    // Check if decryption matches the original plaintext
    assert_eq!(plaintext, my_plaintext, "AES-256 decryption failed.");
  }
}
