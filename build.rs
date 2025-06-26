fn main() {
  // Choose aes key length with default value of 256-bits
  let aes_keylen = std::env::var("AES_KEYLEN").unwrap_or("256".to_string());
  println!("cargo:rerun-if-env-changed=AES_KEYLEN");
  println!("cargo:rustc-cfg=AES_KEYLEN=\"{}\"", aes_keylen);
  println!("cargo::rustc-check-cfg=cfg(AES_KEYLEN, values(\"128\", \"192\", \"256\"))");
}
