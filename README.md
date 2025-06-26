# dbids' AES lib
Simple AES library written for self-educational purposes.

## Building
### Requirements

### Build Library:
```
cargo build
```
#### Switching between AES Keysizes
By default, the build.rs script will build the library as AES-256.  To build with AES-192 or AES-128, export the AES_KEYLEN enviornment variable with the value of 128 or 192.  For example `export AES_KEYLEN=128`.  This can be overriden for a given test on the command line, e.g., `AES_KEYLEN=128 cargo test test_key_exp`.
### Build Main:
TODO: Update after switch to rust
### Execute Main Sample Tests:
TODO: Update after switch to rust
