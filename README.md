# File Encryptor
I wanted to learn Rust, and wrote this File Encryptor for the learning experience. In the future this will serve as a platform for me to try out various related ideas.

## Features

- Platform independent
- Simple command-line interface
- Supports files and directories
- AES-256 in GCM-mode for encryption and integrity
- PBKDF2 (1M rounds) for key generation
- File compression and random padding for masking file length
- Resulting container contains only random, zero cleartext metadata

## Work to be done

- Changing the crate for handling command line argumets
- Maybe replacing the GCM mode with CBC and adding HMAC
- Perhaps adding a second encryption layer (Chacha20 + scrypt)?
- Adding CPU-jitter entropy collector and using it together with OS random for salt & IV generation
- Some minor issues
- ..


## Few words on the security

The fundamental concepts attempt to be somewhat solid. There's nothing wrong with the way things are done. However, there are a few things that need to be considered before using this in any real life scenario. The crates used are not certified in any way, the development and build environments are probably not secured/hardened/isolated, and there's total lack of support.


## License

(c) 2023 TuningSweeper
Released under GNU AGPLv3 License