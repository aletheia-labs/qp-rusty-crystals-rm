import json
import binascii
import random
from bip_utils import Bip39SeedGenerator, Bip32Slip10Secp256k1

# Note: You need to install the bip-utils library: pip install bip-utils
# This is a well-established library for BIP32/BIP39/BIP44 etc. derivations.

# Example mnemonics (add more as needed)
mnemonics = [
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    # Add another for variety: from BIP39 test vectors (without passphrase)
    "legal winner thank year wave sausage worth useful legal winner thank yellow"
]

# Generate random hardened paths (reproducible with seed)
random.seed(42)  # For reproducibility in test vectors
num_paths = 20  # Number of random hardened paths to generate
paths = []
for _ in range(num_paths):
    depth = random.randint(3, 5)  # Random depth between 3 and 5 levels
    path_parts = [f"{random.randint(0, 100)}'" for _ in range(depth)]
    path = 'm/' + '/'.join(path_parts)
    paths.append(path)

data = []

for mnemonic in mnemonics:
    # Generate seed from mnemonic (no passphrase)
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    seed_hex = binascii.hexlify(seed_bytes).decode()

    # Create BIP32 context from seed
    bip32_ctx = Bip32Slip10Secp256k1.FromSeed(seed_bytes)

    for path in paths:
        # Derive child key from path
        child_ctx = bip32_ctx.DerivePath(path)
        child_priv_hex = child_ctx.PrivateKey().Raw().ToHex()

        data.append({
            "seed": seed_hex,
            "path": path,
            "private_key": child_priv_hex
        })

# Write to JSON file
with open('bip44_test_vectors.json', 'w') as f:
    json.dump(data, f, indent=4)

print("JSON file 'bip44_test_vectors.json' has been generated with random hardened paths using bip-utils.")