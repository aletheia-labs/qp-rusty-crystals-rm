// tests/verify_integration_test.rs

use fn_dsa::{DOMAIN_NONE, HASH_ID_ORIGINAL_FALCON};
mod helpers;
use helpers::kat::{TestVector, parse_test_vectors};
use rusty_falcon::{verify, keypair, Error, SignError};
use rusty_falcon_verify::{verify_with_domain_and_hash_id, CRYPTO_PUBLICKEYBYTES};
use rusty_falcon_common::CRYPTO_BYTES;

#[test]
fn test_nist_kat() {
    let kat_data = include_str!("../test_vectors/falcon1024Padded-KAT.rsp");
    let test_vectors = parse_test_vectors(kat_data);
    for test in test_vectors {
        verify_test_vector(&test);
    }
}

/// Verifies a single test vector for Falcon-1024 (padded).
///
/// # Arguments
///
/// * `test` - A reference to the `TestVector` struct containing all the necessary fields.
fn verify_test_vector(test: &TestVector) {
    // Check if the fields have correct lengths
    assert_eq!(
        test.msg.len(),
        test.mlen,
        "Message length mismatch from test vector"
    );
    assert_eq!(
        test.sm.len(),
        test.smlen,
        "Signed message length mismatch from test vector"
    );
    // Check public key length for Falcon-1024 (padded)
    assert_eq!(
        test.pk.len(),
        CRYPTO_PUBLICKEYBYTES,
        "Public key length mismatch"
    );

    let signature = test.extract_signature();

    assert_eq!(
        signature.len(),
        CRYPTO_BYTES,
        "Signature length mismatch"
    );

    // Now call crypto_sign_verify with the extracted signature

    // Note: The NIST KAT files were using the original falcon hash so we have to pass 
    // HASH_ID_ORIGINAL_FALCON to our verify code.
    let result = verify_with_domain_and_hash_id(&signature, &test.msg, &test.pk, &DOMAIN_NONE, &HASH_ID_ORIGINAL_FALCON);

    assert!(
        result.is_ok(),
        "Signature verification failed with error: {:?}",
        result.err()
    );
}

#[test]
fn test_verify_invalid_signature() {
    // Generate Falcon keypair
    let keys_1 = keypair().unwrap();
    let keys_2 = keypair().unwrap();
    let keys_3 = keypair().unwrap();

    // Message to sign
    let message = b"Hello, Resonance!";

    // Sign the message
    let signature = rusty_falcon_sign::sign(message, &keys_2.secret_key)
        .expect("Failed to sign the message");

    // Verify the signature
    let result = verify(&signature, message, &keys_1.public_key);

    assert!(
        result.is_err(),
        "Expected verification to fail, but it succeeded"
    );

    if let Err(Error::SignatureVerification(SignError::BadSignature(err_msg))) = result {
        assert_eq!(
            err_msg, "verification failed",
            "Unexpected error message: {}",
            err_msg
        );
    } else {
        panic!("Unexpected error type for invalid signature");
    }

    let result = verify_with_domain_and_hash_id(&signature, message, &keys_3.public_key, &DOMAIN_NONE, &HASH_ID_ORIGINAL_FALCON);
    assert!(
        result.is_err(),
        "Expected verification to fail, but it succeeded"
    );

    if let Err(Error::SignatureVerification(SignError::BadSignature(err_msg))) = result {
        assert_eq!(
            err_msg, "verification with domain and hash id failed",
            "Unexpected error message: {}",
            err_msg
        );
    } else {
        panic!("Unexpected error type for invalid signature");
    }

}
