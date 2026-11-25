# SPDX-License-Identifier: Apache-2.0
# Copyright (c) Newton Foundation.
#
# Newton Crypto Extensions Test Policy
# Tests the newton.crypto.* built-in functions.

package newton_crypto_test

import future.keywords.if

# Test data generated using Foundry's cast with Anvil account 0
# Private key: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
# Address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266

# keccak256("hello")
test_message_hash := "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"

# Signature of test_message_hash with raw hash signing
# Generated: cast wallet sign --no-hash --private-key <key> <hash>
test_raw_signature := "0x73eebf81a611136662d65778960c853fdcaf6eca86793ed9cabc30f2195937af78a07e601627da5b4cc80c0ab35f6894da19b4a01759d90c101d9c9dd1c6745d1b"

# Signature of "Hello, Newton!" with personal_sign (EIP-191)
# Generated: cast wallet sign --private-key <key> "Hello, Newton!"
test_personal_signature := "0x9af892807bc7b85aa1a2d72afd27ba666c34a91ac1c27084680bd8e8f290a80f264866c894e8aff1fd5bda8a3c211cc5575bd99191a7b43fbf0c559d20ef89671c"

# Expected signer address
expected_signer := "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

# Test: recover signer from raw hash signature
test_recover_signer_basic if {
    signer := newton.crypto.ecdsa_recover_signer(test_raw_signature, test_message_hash)
    count(signer) == 42
    startswith(signer, "0x")
    lower(signer) == lower(expected_signer)
}

# Test: recover signer from personal_sign message
test_recover_signer_personal if {
    message := "Hello, Newton!"
    signer := newton.crypto.ecdsa_recover_signer_personal(test_personal_signature, message)
    count(signer) == 42
    startswith(signer, "0x")
    lower(signer) == lower(expected_signer)
}

# Test: handles signature without 0x prefix
test_signature_no_prefix if {
    sig_no_prefix := "73eebf81a611136662d65778960c853fdcaf6eca86793ed9cabc30f2195937af78a07e601627da5b4cc80c0ab35f6894da19b4a01759d90c101d9c9dd1c6745d1b"
    hash_no_prefix := "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
    signer := newton.crypto.ecdsa_recover_signer(sig_no_prefix, hash_no_prefix)
    count(signer) == 42
    lower(signer) == lower(expected_signer)
}

# Test: both functions return valid address format
test_address_format_consistency if {
    signer1 := newton.crypto.ecdsa_recover_signer(test_raw_signature, test_message_hash)
    signer2 := newton.crypto.ecdsa_recover_signer_personal(test_personal_signature, "Hello, Newton!")
    
    startswith(signer1, "0x")
    startswith(signer2, "0x")
    count(signer1) == 42
    count(signer2) == 42
    lower(signer1) == lower(signer2)
}
