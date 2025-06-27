# dbids' AES lib
Simple AES library written in Rust for self-educational purposes.

Made with the goal of being straightforward at the cost of performance, keys are expanded on
every encryption or decryption.

Mode of operation support status:
| | 128 | 192 | 256 |
| :---: | :---: | :---: | :---: |
| AES | ✅ | ✅ | ✅ |
| AES-ECB | ✅ | ✅ | ✅ |
| AES-CBC | ❌ | ❌ | ❌ |
| AES-CTR | ❌ | ❌ | ❌ |
| AES-GCM | ❌ | ❌ | ❌ |
| AES-GCM-SIV | ❌ | ❌ | ❌ |

## Building
### Requirements
Simply a standard rust enviornment.  Tested locally on x86.

### Build Library:
```
cargo build
```
## Testing
### Unit Tests:
To run all tests use:
```
cargo test
```
To run a specific test use:
```
cargo test TESTNAME
```
## Integration Tests:
TODO
