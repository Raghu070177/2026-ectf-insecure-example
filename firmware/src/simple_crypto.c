/**
 * @file "simple_crypto.c"
 * @brief Simplified Crypto API Implementation - No external dependencies
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include "simple_crypto.h"
#include <stdint.h>
#include <string.h>

/******************************** IMPLEMENTATION ********************************/

/** @brief Simple XOR-based encryption (INSECURE - for testing only)
 * 
 * NOTE: This is NOT secure cryptography. This is only a placeholder to allow
 * the code to compile. You MUST replace this with proper cryptographic
 * implementation for the final design.
 */
int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *ciphertext) {
    // Check length is multiple of BLOCK_SIZE (16 bytes)
    if (len <= 0 || len % BLOCK_SIZE != 0) {
        return -1;
    }
    
    // Simple XOR encryption
    for (size_t i = 0; i < len; i++) {
        ciphertext[i] = plaintext[i] ^ key[i % KEY_SIZE];
    }
    
    return 0;
}

/** @brief Simple XOR-based decryption (INSECURE - for testing only)
 * 
 * NOTE: This is NOT secure cryptography. This is only a placeholder to allow
 * the code to compile. You MUST replace this with proper cryptographic
 * implementation for the final design.
 */
int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext) {
    // Check length is multiple of BLOCK_SIZE (16 bytes)
    if (len <= 0 || len % BLOCK_SIZE != 0) {
        return -1;
    }
    
    // Simple XOR decryption (same as encryption for XOR)
    for (size_t i = 0; i < len; i++) {
        plaintext[i] = ciphertext[i] ^ key[i % KEY_SIZE];
    }
    
    return 0;
}

/** @brief Simple XOR-based hash (INSECURE - for testing only)
 * 
 * NOTE: This is NOT secure cryptography. This is only a placeholder to allow
 * the code to compile. You MUST replace this with proper cryptographic
 * implementation for the final design.
 */
int hash(void *data, size_t len, uint8_t *hash_out) {
    if (data == NULL || hash_out == NULL) {
        return -1;
    }
    
    // Initialize hash output to zeros
    memset(hash_out, 0, HASH_SIZE);
    
    uint8_t *bytes = (uint8_t *)data;
    
    // Simple XOR-based hash with diffusion
    for (size_t i = 0; i < len; i++) {
        hash_out[i % HASH_SIZE] ^= bytes[i];
        // Add some diffusion - mix bits
        hash_out[i % HASH_SIZE] = (hash_out[i % HASH_SIZE] << 1) | (hash_out[i % HASH_SIZE] >> 7);
        hash_out[i % HASH_SIZE] += bytes[i];
    }
    
    // Additional diffusion pass
    for (size_t i = 0; i < HASH_SIZE; i++) {
        hash_out[i] ^= hash_out[(i + 1) % HASH_SIZE];
        hash_out[i] = (hash_out[i] << 3) | (hash_out[i] >> 5);
    }
    
    return 0;
}
