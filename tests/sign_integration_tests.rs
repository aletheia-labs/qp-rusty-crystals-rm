// tests/sign_integration_tests.rs

use rusty_crystals_dilithium::{sign, sign_combined, verify};
use rusty_crystals_hdwallet::{HDLattice, generate_mnemonic};
use fn_dsa::{DOMAIN_NONE, HASH_ID_RAW};

#[test]
fn test_sign() {
    // Step 1: Generate a random mnemonic and derive Falcon keypair
    let mnemonic = generate_mnemonic(24).expect("Failed to generate mnemonic");
    let hd_lattice = HDLattice::from_mnemonic(&mnemonic, None)
        .expect("Failed to create HDLattice from mnemonic");

    let dilithium_keypair = hd_lattice.generate_keys()
        .expect("Failed to generate Dilithium keypair");

    let public_key = dilithium_keypair.public_key;
    let secret_key = dilithium_keypair.secret_key;

    // Step 2: Define the message to sign
    let message = b"Hello, Dilithium!";

    // Step 3: Sign the message using the secret key
    let signature = sign(message, &secret_key)
        .expect("Signing failed");

    // Step 4: Verify the signature using the public key
    let verify_result = verify_with_domain_and_hash_id(
        &signature,
        message,
        &public_key,
        &DOMAIN_NONE,
        &HASH_ID_RAW,
    );

    assert!(
        verify_result.is_ok(),
        "Signature verification failed with error: {:?}",
        verify_result.err()
    );
}

#[test]
fn test_sign_combined() {
    // Step 1: Generate a random mnemonic and derive Dilithium keypair
    let mnemonic = generate_mnemonic(24).expect("Failed to generate mnemonic");
    let hd_lattice = HDLattice::from_mnemonic(&mnemonic, None)
        .expect("Failed to create HDLattice from mnemonic");

    let dilithium_keypair = hd_lattice.generate_keys()
        .expect("Failed to generate Dilithium keypair");

    let public_key = dilithium_keypair.public_key;
    let secret_key = dilithium_keypair.secret_key;

    // Step 2: Define the message to sign
    let message = b"Hello, Dilithium!";

    // Step 3: Sign the message and combine it with the original message
    let (signed_message, signature_length) =
        sign_combined(message, &secret_key)
            .expect("Signing combined message failed");

    // Step 4: Split the signed message into signature and original message
    let (signature, original_message) = 
        signed_message.split_at(signature_length);

    // Step 5: Verify the signature using the public key
    let verify_result = verify(
        signature,
        original_message,
        &public_key
    );

    assert!(
        verify_result.is_ok(),
        "Signature verification failed with error: {:?}",
        verify_result.err()
    );
}
