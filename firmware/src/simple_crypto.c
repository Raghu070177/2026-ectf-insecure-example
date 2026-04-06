#include "simple_crypto.h"
#include <stdint.h>
#include <string.h>

int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *ciphertext) {
    Aes ctx;
    if (len <= 0 || len % 16) return -1;
    if (wc_AesSetKey(&ctx, key, 16, NULL, AES_ENCRYPTION) != 0) return -1;
    for (int i = 0; i < len; i += 16) {
        wc_AesEncryptDirect(&ctx, ciphertext + i, plaintext + i);
    }
    return 0;
}

int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext) {
    Aes ctx;
    if (len <= 0 || len % 16) return -1;
    if (wc_AesSetKey(&ctx, key, 16, NULL, AES_DECRYPTION) != 0) return -1;
    for (int i = 0; i < len; i += 16) {
        wc_AesDecryptDirect(&ctx, plaintext + i, ciphertext + i);
    }
    return 0;
}

int hash(void *data, size_t len, uint8_t *hash_out) {
    return wc_Md5Hash((uint8_t *)data, len, hash_out);
}
