# Rusty Crystals

A Rust implementation of the ML-DSA (formerly "dilithium") post-quantum digital signature scheme with hierarchical deterministic (HD) wallet support.

Specifically, this wallet imitates BIP-32 and BIP-39 (but not BIP-44) in its derivation of ml-dsa keys.

The ml-dsa code was lifted with minimal changes from [Quantum Blockchain's port](https://github.com/Quantum-Blockchains/dilithium)
of [pq-crystals](https://github.com/pq-crystals/dilithium) to Rust.


## Overview

This workspace contains two crates that can be used independently or together:

- `rusty-crystals` - Main crate that re-exports all functionality
- `rusty-crystals-dilithium` - Key generation, signing, signature verification
- `rusty-crystals-hdwallet` - HD wallet implementation for ML-DSA

## Usage

Add to your `Cargo.toml`:
```toml
[dependencies]
rusty-crystals = "0.1.0"
```

### Basic Example

```rust
use rusty_crystals_dilithium::{keypair, sign, verify};

let keypair = Keypair::generate(Some(&seed));
let signature = keypair.sign(&msg);
let is_verified = keypair.public.verify(&msg, &signature);
```

### HD Wallet Example

```rust
use rusty_falcon_hdwallet::{generate_mnemonic, HDLattice};

// Generate a new mnemonic
let mnemonic = generate_mnemonic(24).expect("Failed to generate mnemonic");

// Create HD wallet
let hd = HDLattice::from_mnemonic(&mnemonic, None)
    .expect("Failed to create HD wallet");

// Generate master keys
let master_keys = hd.generate_keys();

// Derive child keys
let child_keys = hd.generate_derived_keys("0/1/2")
    .expect("Failed to derive child keys");
```

## Subcrates

### rusty-crystals-dilithium
Key generation functionality including:
- Random keypair generation
- Deterministic key generation from seed
- Signing messages
- Verifying signatures

### rusty-crystals-hdwallet
HD wallet implementation featuring:
- BIP39 mnemonic generation
- Hierarchical deterministic key derivation
- Hardened key derivation paths


## Testing

Run all tests with:

```bash
cargo test --workspace
```

For test coverage:

```bash
cargo install cargo-tarpaulin
cargo tarpaulin --workspace
```

### NIST KAT tests

test_nist_kat test case in 'verify_integration_tests.rs' covers the NIST KAT test cases generated from the PQCrystals 
for ML-DSA-65. We exported the test file from PQ-Crystals c code, and are importing and testing against it here. 

To regenerate this file...
```
git clone https://github.com/pq-crystals/dilithium
cd dilithium/ref
make nistkat
./nistkat/PQCgenKAT_sign5 
cp ./nistkat/PQCsignKAT_Dilithium5.rsp ???
```

## Code Coverage
This repository has 100% code coverage for all critical logic and functionality. 
```./coverage.sh```

## License

[Apache License, Version 2.0](LICENSE).

## Acknowledgements

Falcon signatures are generated, verified, and signed using the reference implementation in the [rust-fn-dsa crate](https://crates.io/crates/rust-fn-dsa). We would like to thank [Thomas Pornin](https://github.com/pornin) for his work on this invaluable library.
